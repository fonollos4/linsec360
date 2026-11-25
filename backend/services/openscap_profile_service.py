"""Download and validate distro-provided OpenSCAP SCAP data streams.

The bundled CIS profiles are the official data streams shipped by Ubuntu and
CentOS Stream. They replace the previous hand-written XCCDF tailoring files:
the exact archive, digest, member and CIS profile are pinned here, so refresh
is reproducible and cannot fetch arbitrary content.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import struct
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from ..config import get_settings
from ..errors import DomainError, IntegrationUnavailable

logger = logging.getLogger(__name__)

DOWNLOAD_TIMEOUT_SECONDS = 120
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ProfileSource:
    """An immutable, auditable source for one bundled profile."""

    name: str
    archive: str
    source_url: str
    sha256: str
    member: str
    profile_id: str
    size_bytes: int


PROFILE_SOURCES: tuple[ProfileSource, ...] = (
    ProfileSource(
        name="cis_ubuntu.xml",
        archive="deb",
        source_url=(
            "http://archive.ubuntu.com/ubuntu/pool/universe/s/"
            "scap-security-guide/ssg-debderived_0.1.82-1_all.deb"
        ),
        sha256=(
            "7fe93920a704e12b40ead4b70cd6344269dea927af2e208cd5f07a557f4f73a9"
        ),
        member="./usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
        profile_id="xccdf_org.ssgproject.content_profile_cis_level1_server",
        size_bytes=12_593_118,
    ),
    ProfileSource(
        name="cis_rhel.xml",
        archive="rpm",
        source_url=(
            "https://mirror.stream.centos.org/9-stream/AppStream/x86_64/"
            "os/Packages/scap-security-guide-0.1.82-1.el9.noarch.rpm"
        ),
        sha256=(
            "798d7641859da2f875c66b1cf0399489570d9b8d55cdddfce2c27f26a6fab496"
        ),
        member="./usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
        profile_id="xccdf_org.ssgproject.content_profile_cis_server_l1",
        size_bytes=28_867_269,
    ),
)

SOURCES_BY_NAME = {source.name: source for source in PROFILE_SOURCES}


def _zstd_stream(data: bytes):
    """Return a streaming reader for a zstd frame without a content size."""
    try:
        import zstandard
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise IntegrationUnavailable(
            "zstandard is required to read distro SCAP packages"
        ) from exc
    return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data))


def _ar_members(archive: bytes):
    """Yield (name, payload) pairs from a Unix ar archive."""
    if not archive.startswith(b"!<arch>\n"):
        raise DomainError("downloaded Ubuntu package is not an ar archive")
    offset = 8
    while offset + 60 <= len(archive):
        header = archive[offset : offset + 60]
        try:
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise DomainError("downloaded Ubuntu package has an invalid ar header") from exc
        name = header[:16].decode("ascii", errors="replace").strip()
        start = offset + 60
        yield name, archive[start : start + size]
        offset = start + size + (size % 2)


def _tar_member(tar: tarfile.TarFile, member: str) -> bytes | None:
    for entry in tar:
        if entry.name != member or not entry.isfile():
            continue
        extracted = tar.extractfile(entry)
        return extracted.read() if extracted is not None else None
    return None


def _extract_deb(archive: bytes, member: str) -> bytes:
    """Extract one member from a .deb data archive (zstd, xz or gzip)."""
    for name, payload in _ar_members(archive):
        if not name.startswith("data.tar"):
            continue
        if name.endswith(".zst"):
            with tarfile.open(fileobj=_zstd_stream(payload), mode="r|") as tar:
                content = _tar_member(tar, member)
        else:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tar:
                content = _tar_member(tar, member)
        if content is not None:
            return content
    raise DomainError(f"SCAP data stream {member} is missing from the Ubuntu package")


def _rpm_header_end(data: bytes, offset: int) -> int:
    """Return the byte offset just after an RPM header."""
    if data[offset : offset + 8] != bytes.fromhex("8eade80100000000"):
        raise DomainError("downloaded RHEL package has an invalid RPM header")
    index_count, store_size = struct.unpack(">II", data[offset + 8 : offset + 16])
    store = offset + 16 + 16 * index_count
    return store + store_size


def _extract_rpm(archive: bytes, member: str) -> bytes:
    """Extract one member from a zstd-compressed RPM cpio payload."""
    signature_end = _rpm_header_end(archive, 96)
    header_start = (signature_end + 7) // 8 * 8
    header_end = _rpm_header_end(archive, header_start)
    payload = _zstd_stream(archive[header_end:]).read()

    offset = 0
    while offset + 110 <= len(payload):
        magic = payload[offset : offset + 6]
        if magic not in (b"070701", b"070702"):
            break
        try:
            fields = [
                int(payload[offset + 6 + index * 8 : offset + 14 + index * 8], 16)
                for index in range(13)
            ]
        except ValueError as exc:
            raise DomainError("downloaded RHEL package has an invalid cpio header") from exc
        file_size, name_size = fields[6], fields[11]
        name_start = offset + 110
        name = payload[name_start : name_start + name_size - 1].decode(
            "utf-8", errors="replace"
        )
        content_start = name_start + name_size
        if name == member:
            return payload[content_start : content_start + file_size]
        if name == "TRAILER!!!":
            break
        offset = (content_start + 3) // 4 * 4 + (file_size + 3) // 4 * 4
    raise DomainError(f"SCAP data stream {member} is missing from the RHEL package")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def validate_data_stream(content: bytes, profile_id: str) -> None:
    """Reject tailoring files and data streams without the pinned CIS profile."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise DomainError("downloaded SCAP content is not valid XML") from exc
    if _local_name(root.tag) != "data-stream-collection":
        raise DomainError(
            "downloaded SCAP content is not a data stream; tailoring files "
            "cannot replace the bundled profiles"
        )
    profiles = {
        element.attrib.get("id", "")
        for element in root.iter()
        if _local_name(element.tag) == "Profile"
    }
    if profile_id not in profiles:
        raise DomainError(
            f"downloaded SCAP data stream does not contain {profile_id}"
        )


def _fetch_profile(source: ProfileSource) -> bytes:
    """Download a pinned distro archive and extract its SCAP data stream."""
    try:
        response = httpx.get(
            source.source_url,
            timeout=DOWNLOAD_TIMEOUT_SECONDS,
            follow_redirects=True,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise IntegrationUnavailable(
            f"unable to download {source.name} from the distribution"
        ) from exc
    archive = response.content
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise DomainError(f"downloaded archive for {source.name} is unexpectedly large")
    digest = hashlib.sha256(archive).hexdigest()
    if digest != source.sha256:
        raise DomainError(
            f"checksum mismatch for {source.name}: expected {source.sha256}, got {digest}"
        )

    if source.archive == "deb":
        content = _extract_deb(archive, source.member)
    elif source.archive == "rpm":
        content = _extract_rpm(archive, source.member)
    else:  # pragma: no cover - catalogue is fixed
        raise DomainError(f"unsupported archive type for {source.name}")
    if len(content) != source.size_bytes:
        raise DomainError(
            f"unexpected size for {source.name}: expected {source.size_bytes}, "
            f"got {len(content)}"
        )
    validate_data_stream(content, source.profile_id)
    return content


def catalog() -> list[dict]:
    """Describe the pinned profiles without performing any network request."""
    return [
        {
            "name": source.name,
            "archive": source.archive,
            "source_url": source.source_url,
            "sha256": source.sha256,
            "profile_id": source.profile_id,
            "size_bytes": source.size_bytes,
            "updated_at": None,
        }
        for source in PROFILE_SOURCES
    ]


def _atomic_write(directory: Path, name: str, content: bytes) -> None:
    """Replace one profile in place, never leaving a partially written file."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{name}.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o640)
        os.replace(temporary_name, directory / name)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def refresh(profiles: Sequence[str] | None = None) -> list[dict]:
    """Download, validate and atomically overwrite the requested profiles."""
    requested = list(PROFILE_SOURCES) if not profiles else [
        SOURCES_BY_NAME[name] for name in profiles
    ]
    directory = get_settings().openscap_profile_dir
    results: list[dict] = []
    for source in requested:
        content = _fetch_profile(source)
        validate_data_stream(content, source.profile_id)
        _atomic_write(directory, source.name, content)
        updated_at = datetime.now(UTC)
        logger.info(
            "openscap profile refreshed",
            extra={
                "profile": source.name,
                "profile_id": source.profile_id,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            },
        )
        results.append(
            {
                "name": source.name,
                "archive": source.archive,
                "source_url": source.source_url,
                "sha256": hashlib.sha256(content).hexdigest(),
                "profile_id": source.profile_id,
                "size_bytes": len(content),
                "updated_at": updated_at,
            }
        )
    return results
