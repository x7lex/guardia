"""Exercise the real static parser through the upload API, without running a PE."""

import hashlib
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from fastapi.testclient import TestClient

from backend.api import app


def minimal_pe():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<III", data, optional + 16, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<III", data, optional + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 224
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 1, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return bytes(data)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def upload(self, content, name="folder/demo.exe", headers=None):
        return self.client.post(
            "/scan",
            params={"name": name},
            content=content,
            headers=headers or {"Content-Type": "application/octet-stream"},
        )

    def test_real_pe_report_and_temp_cleanup(self):
        from backend import api

        original = api.output
        paths = []

        async def analyze(path):
            paths.append(path)
            return await original(path)

        with patch.object(api, "output", side_effect=analyze):
            response = self.upload(minimal_pe())
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["status"], "scanned")
        self.assertEqual(
            result["report"]["analysis"]["file"]["file_path"], "folder/demo.exe"
        )
        self.assertEqual(
            result["report"]["analysis"]["file"]["sha256"],
            hashlib.sha256(minimal_pe()).hexdigest(),
        )
        self.assertIn("score", result["report"]["risk_assessment"]["risk"])
        self.assertTrue(all(not path.exists() for path in paths))

    def test_unsupported_and_empty_files_are_explicitly_skipped(self):
        for content in (b"", b"not an executable"):
            result = self.upload(content).json()
            self.assertEqual(result["status"], "skipped")
            self.assertTrue(result["reason"])

    def test_paths_cannot_read_or_write_server_files(self):
        for name in (
            "../demo.exe",
            "/etc/passwd",
            "C:\\test.exe",
            "folder/../demo.exe",
        ):
            self.assertEqual(self.upload(b"x", name).status_code, 400)
        self.assertEqual(
            self.client.post("/path", json={"path": "/etc"}).status_code, 404
        )

    def test_size_limit_enforced_without_relying_on_declared_size(self):
        with patch("backend.api.MAX_FILE_BYTES", 4):
            self.assertEqual(self.upload(b"12345").status_code, 413)
            response = self.upload(iter([b"123", b"456"]))
            self.assertEqual(response.status_code, 413)

    def test_wrong_content_type_and_missing_name(self):
        self.assertEqual(
            self.upload(b"x", headers={"Content-Type": "text/plain"}).status_code, 415
        )
        self.assertEqual(self.client.post("/scan", content=b"x").status_code, 422)
        self.assertEqual(self.client.get("/health").json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
