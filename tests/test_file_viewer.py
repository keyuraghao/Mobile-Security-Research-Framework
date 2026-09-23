"""File viewer: Android binary XML is decoded; other binaries get a hex dump."""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from msrf.engines.sast import _AXML_MAGIC, _decode_axml, _hexdump

DIVA = Path(__file__).resolve().parent.parent / "Test_Aplication" / "diva-beta.apk"


def test_hexdump_has_offset_hex_and_text_columns():
    out = _hexdump(b"PK\x03\x04hello world!!!!!" + bytes(range(4)))
    first, second = out.splitlines()
    assert first.startswith("00000000  50 4b 03 04 68 65")
    assert first.endswith("PK..hello world!")
    assert second.startswith("00000010  ")


@pytest.mark.skipif(not DIVA.is_file(), reason="sample APK not present")
def test_binary_manifest_decodes_to_readable_xml():
    pytest.importorskip("mobsf.StaticAnalyzer.tools.androguard4.axml")
    raw = zipfile.ZipFile(DIVA).read("AndroidManifest.xml")
    assert raw[:4] == _AXML_MAGIC
    xml = _decode_axml(raw)
    assert xml is not None
    assert "<manifest" in xml
    assert "jakhar.aseem.diva" in xml


def test_decode_axml_rejects_garbage():
    assert _decode_axml(_AXML_MAGIC + b"\x00" * 8) is None
