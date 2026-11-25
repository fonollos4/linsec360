"""Authenticated interactive SSH terminal over WebSocket.

The session uses the service account key provisioned by the administrator.
SSH host keys are not scanned or compared; this endpoint only relies on the
pre-provisioned account/key pair.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import struct
import subprocess
import termios
from typing import Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..security import get_current_user
from ..services import audit_service, host_service

router = APIRouter(prefix="/hosts", tags=["terminal"])


def _ssh_command(host: models.Host) -> list[str]:
    settings = get_settings()
    private_key = settings.ansible_ssh_private_key_path.expanduser()
    return [
        "ssh",
        "-tt",
        "-i",
        str(private_key),
        "-p",
        str(host.ansible_port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        f"{host.ansible_user}@{host.ip}",
    ]


@router.websocket("/{host_id}/terminal/ws")
async def host_terminal(
    websocket: WebSocket,
    host_id: int,
    db: Session = Depends(get_db),
) -> None:
    user: models.User | None = None
    try:
        user = get_current_user(websocket, db)  # type: ignore[arg-type]
        if user.role not in {"admin", "operator"}:
            await websocket.close(code=4403, reason="insufficient permissions")
            return
        host = host_service.get_host(db, host_id)
    except Exception:
        await websocket.close(code=4401, reason="authentication required")
        return

    await websocket.accept()
    audit_service.record(
        db,
        actor=user,
        action="host.terminal_open",
        target_type="host",
        target_id=host.id,
        data={"host": host.name, "ip": host.ip, "user": host.ansible_user},
        request=websocket,  # type: ignore[arg-type]
    )
    db.commit()

    loop = asyncio.get_running_loop()
    master_fd, slave_fd = pty.openpty()
    os.set_blocking(master_fd, False)
    process = subprocess.Popen(
        _ssh_command(host),
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
    )
    os.close(slave_fd)
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def _read_ready() -> None:
        try:
            data = os.read(master_fd, 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if data:
            queue.put_nowait(data)
        else:
            loop.remove_reader(master_fd)
            queue.put_nowait(None)

    loop.add_reader(master_fd, _read_ready)

    async def _forward_output() -> None:
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            try:
                await websocket.send_json(
                    {"type": "output", "data": chunk.decode("utf-8", "replace")}
                )
            except Exception:
                break

    sender = asyncio.create_task(_forward_output())
    await websocket.send_json(
        {
            "type": "status",
            "message": f"Session ouverte sur {host.name} avec le compte de service {host.ansible_user}.",
        }
    )

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message: dict[str, Any] = json.loads(raw)
            except (ValueError, TypeError):
                continue
            kind = message.get("type")
            if kind == "input":
                data = message.get("data", "")
                if isinstance(data, str) and process.poll() is None:
                    try:
                        os.write(master_fd, data.encode("utf-8"))
                    except OSError:
                        pass
            elif kind == "resize":
                rows = int(message.get("rows", 24))
                cols = int(message.get("cols", 80))
                rows = max(1, min(rows, 200))
                cols = max(1, min(cols, 400))
                try:
                    fcntl.ioctl(
                        master_fd,
                        termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0),
                    )
                except OSError:
                    pass
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        loop.remove_reader(master_fd)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        os.close(master_fd)
        sender.cancel()
        audit_service.record(
            db,
            actor=user,
            action="host.terminal_close",
            target_type="host",
            target_id=host.id,
            data={"host": host.name},
            request=websocket,  # type: ignore[arg-type]
        )
        db.commit()
