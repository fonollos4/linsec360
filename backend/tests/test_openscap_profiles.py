"""Tests for distro-provided OpenSCAP profile downloads."""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.config import get_settings
from backend.services import openscap_profile_service as profile_service

from .conftest import VIEWER_PASSWORD

ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "config" / "openscap" / "profiles"

MINIMAL_DATASTREAM = b"""<?xml version="1.0" encoding="utf-8"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
                           xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                           id="scap_org.open-scap_datastream_collection_test">
  <ds:component id="scap_org.open-scap_cref_test">
    <xccdf:Benchmark id="xccdf_org.ssgproject.content_benchmark_test">
      <xccdf:Profile id="xccdf_org.ssgproject.content_profile_cis_level1_server"/>
    </xccdf:Benchmark>
  </ds:component>
</ds:data-stream-collection>
"""

TAILORING = b"""<?xml version="1.0" encoding="utf-8"?>
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                 id="xccdf_linsec_tailoring_test">
  <xccdf:benchmark href="ssg-ubuntu2204-ds.xml"/>
</xccdf:Tailoring>
"""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@pytest.fixture(autouse=True)
def restore_temp_profiles():
    """The API writes into a test copy of the profile directory."""
    directory = get_settings().openscap_profile_dir
    directory.mkdir(parents=True, exist_ok=True)
    originals = {
        name.name: name.read_bytes()
        for name in directory.glob("*.xml")
    }
    yield directory
    for name, content in originals.items():
        (directory / name).write_bytes(content)


def test_bundled_profiles_are_distro_data_streams() -> None:
    expected = {
        "cis_ubuntu.xml": "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "cis_rhel.xml": "xccdf_org.ssgproject.content_profile_cis_server_l1",
    }
    for filename, profile_id in expected.items():
        content = (PROFILE_DIR / filename).read_bytes()
        root = ET.fromstring(content)

        assert _local_name(root.tag) == "data-stream-collection"
        assert profile_id.encode("utf-8") in content
        assert b"xccdf_linsec_tailoring" not in content


def test_profile_catalog_reports_provenance_without_downloading(
    client: TestClient, csrf_headers
) -> None:
    response = client.get(
        "/api/v1/compliance/profiles/catalog", headers=csrf_headers()
    )
    assert response.status_code == 200, response.text
    profiles = {item["name"]: item for item in response.json()}

    assert set(profiles) == {"cis_ubuntu.xml", "cis_rhel.xml"}
    assert profiles["cis_ubuntu.xml"]["archive"] == "deb"
    assert profiles["cis_rhel.xml"]["archive"] == "rpm"
    assert "archive.ubuntu.com" in profiles["cis_ubuntu.xml"]["source_url"]
    assert "mirror.stream.centos.org" in profiles["cis_rhel.xml"]["source_url"]
    assert profiles["cis_ubuntu.xml"]["sha256"] is not None


def test_refresh_overwrites_the_requested_profile_atomically(
    client: TestClient, csrf_headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = csrf_headers()
    calls: list[str] = []
    monkeypatch.setattr(
        profile_service,
        "_fetch_profile",
        lambda source: calls.append(source.name) or MINIMAL_DATASTREAM,
    )
    target = get_settings().openscap_profile_dir / "cis_ubuntu.xml"
    rhel = get_settings().openscap_profile_dir / "cis_rhel.xml"
    rhel_before = rhel.read_bytes()

    response = client.post(
        "/api/v1/compliance/profiles/refresh",
        headers=headers,
        json={"profiles": ["cis_ubuntu.xml"]},
    )
    assert response.status_code == 200, response.text
    assert calls == ["cis_ubuntu.xml"]
    assert target.read_bytes() == MINIMAL_DATASTREAM
    assert rhel.read_bytes() == rhel_before

    payload = {item["name"]: item for item in response.json()}
    assert payload["cis_ubuntu.xml"]["sha256"] == hashlib.sha256(
        MINIMAL_DATASTREAM
    ).hexdigest()
    assert payload["cis_ubuntu.xml"]["updated_at"] is not None

    audit = client.get("/api/v1/audit?limit=20", headers=headers)
    assert any(
        entry["action"] == "compliance.profile.refresh"
        and "cis_ubuntu.xml" in str(entry.get("data"))
        for entry in audit.json()
    )


def test_refresh_rejects_a_non_datastream_without_overwriting(
    client: TestClient, csrf_headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = csrf_headers()
    monkeypatch.setattr(
        profile_service, "_fetch_profile", lambda source: TAILORING
    )
    target = get_settings().openscap_profile_dir / "cis_ubuntu.xml"
    before = target.read_bytes()

    response = client.post(
        "/api/v1/compliance/profiles/refresh",
        headers=headers,
        json={"profiles": ["cis_ubuntu.xml"]},
    )
    assert response.status_code == 400
    assert "data stream" in response.json()["error"]["message"].lower()
    assert target.read_bytes() == before


def test_profile_refresh_requires_admin(client: TestClient, csrf_headers) -> None:
    headers = csrf_headers("viewer", VIEWER_PASSWORD)
    response = client.post(
        "/api/v1/compliance/profiles/refresh",
        headers=headers,
        json={"profiles": ["cis_ubuntu.xml"]},
    )
    assert response.status_code == 403
