"""Synthetic source only. Nothing in these fixtures is run by the scanner."""

import ast
import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from backend import deobfuscator as deob
from backend.scripts import inspect_python


class DeobfuscatorTests(unittest.TestCase):
    def recover(self, source):
        report = deob.analyze_python_source(source)
        json.dumps(report)
        coverage = report["coverage"]
        self.assertEqual(coverage["expressions_examined"], coverage["expressions_resolved"] + coverage["expressions_unresolved"])
        self.assertNotIn("malware", report)
        self.assertNotIn("risk_score", report)
        return report

    def strings(self, source):
        return {item["value"] for item in self.recover(source)["decoded_strings"]}

    def test_constant_transformations(self):
        cases = {
            'a="sub"; b="process"; c=a+b': "subprocess",
            'x="".join(chr(i) for i in [99,109,100])': "cmd",
            'x="llehsrewop"[::-1]': "powershell",
            'x=base64.b64decode("c3VicHJvY2Vzcw==")': "subprocess",
            'x=bytes.fromhex("73756270726f63657373").decode()': "subprocess",
            'x=bytearray.fromhex("636d64").decode()': "cmd",
            'x="".join(chr(i ^ 22) for i in [117,123,114])': "cmd",
            'x=bytes([0x63, 0x6d, 0x64]).decode()': "cmd",
            'x="".join(map(chr,[99,109,100]))': "cmd",
            'x="".join(reversed("dmc"))': "cmd",
            'x="CMd".replace("CM", "cm")': "cmd",
            'x="hello".encode().decode()': "hello",
            'x=chr(ord("b") + 1) + chr(109) + chr(100)': "cmd",
            'a="cmd"; x=f"{a}.exe"': "cmd.exe",
            'x={"name": "cmd.exe"}["name"]': "cmd.exe",
            'x=("unused", "cmd.exe")[1]': "cmd.exe",
            'x=base64.urlsafe_b64decode("c3VicHJvY2Vzcw==").decode()': "subprocess",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertIn(expected, self.strings(source))

    def test_nested_decoders(self):
        encoded = base64.b64encode(b"73756270726f63657373").decode()
        report = self.recover(f'import base64\nx=bytes.fromhex(base64.b64decode({encoded!r}).decode()).decode()')
        self.assertIn("subprocess", {item["value"] for item in report["decoded_strings"]})
        self.assertTrue(report["obfuscation"]["multiple_decode_layers"])
        encoded = base64.b64encode(b"llehsrewop").decode()
        self.assertIn("powershell", self.strings(f'x=base64.b64decode({encoded!r}).decode()[::-1]'))

    def test_import_aliases(self):
        for expression in ('__import__', 'builtins.__dict__["__import__"]',
                           'getattr(__builtins__, "__import__")',
                           'globals()["__builtins__"]["__import__"]',
                           'locals()["__builtins__"].__import__'):
            with self.subTest(expression=expression):
                report = self.recover(f'imp={expression}\nmod=imp("sub"+"process")\ng=getattr\nf=g(mod,"Po"+"pen")\nf("echo benign")')
                self.assertIn({"name": "subprocess", "source": "dynamic_resolved", "confidence": "high"}, report["imports"])
                self.assertIn("subprocess.Popen", report["resolved_calls"])
                self.assertIn({"object": "subprocess", "attribute": "Popen", "confidence": "high"}, report["resolved_attributes"])

    def test_normal_imports_and_base64_aliases(self):
        report = self.recover('from base64 import b64decode as d\nimport sys\nfrom os import system\nm=__import__(d("c3VicHJvY2Vzcw==").decode())')
        self.assertEqual({x["name"] for x in report["imports"]}, {"base64", "sys", "os", "subprocess"})

    def test_unknown_attribute_object_and_lookup_is_not_execution(self):
        report = self.recover('getattr(obj,"Po"+"pen")')
        self.assertEqual(report["resolved_attributes"], [{"object": None, "attribute": "Popen", "confidence": "medium"}])
        report = self.recover('import subprocess\ngetattr(subprocess,"Popen")')
        self.assertNotIn("subprocess.Popen", report["resolved_calls"])

    def test_branches_reassignment_and_shadowing(self):
        cases = [
            'x="subprocess"\nif condition:\n x="os"\nelse:\n x="socket"\nm=__import__(x)',
            'x="subprocess"\nx=unknown_function()\nm=__import__(x)',
            'chr=unknown\nx=chr(99)',
            'base64=unknown\nx=base64.b64decode("c3VicHJvY2Vzcw==")',
            'def f(__import__):\n m=__import__("subprocess")',
            'x="subprocess"\nfor i in unknown:\n x="os"\nm=__import__(x)',
            'x="subprocess"\ndel x\nm=__import__(x)',
            'x="subprocess"\nx += unknown\nm=__import__(x)',
        ]
        for source in cases:
            with self.subTest(source=source):
                report = self.recover(source)
                self.assertFalse(any(x["source"] == "dynamic_resolved" for x in report["imports"]))
                self.assertGreater(report["coverage"]["expressions_unresolved"], 0)
        self.assertIn("subprocess", self.strings('x="wrong"\nx="sub"+"process"'))

    def test_function_local_and_outer_builtin_shadowing(self):
        for source in ('chr=unknown\ndef f():\n x=chr(99)',
                       'def f():\n x=chr(99)\n def chr(x):\n  pass',
                       'def f():\n x=chr(99)\n import other as chr'):
            with self.subTest(source=source):
                self.assertNotIn("c", self.strings(source))

    def test_mutation_and_unknown_methods_do_not_fold(self):
        for mutation in ('b[0]="socket"', 'b.append("socket")', 'unknown(b)'):
            report = self.recover('a=["subprocess"]; b=a\n' + mutation + '\nm=__import__(a[0])')
            self.assertFalse(any(x["source"] == "dynamic_resolved" for x in report["imports"]))
        self.assertNotIn("subprocess", self.strings('obj=unknown\nx=obj.fromhex("73756270726f63657373").decode()'))

    def test_unknown_slice_bound_is_not_omitted(self):
        report = self.recover('x="subprocess"[unknown:]\nm=__import__(x)')
        self.assertEqual(report["imports"], [])

    def test_resource_limits(self):
        cases = ('x="A" * 999999999999', 'x=[1] * 999999999999',
                 'x=1 << 999999999999', 'x="a".replace("", "b"*64000)',
                 'x=chr(1 << 127)')
        for source in cases:
            with self.subTest(source=source):
                report = self.recover(source)
                self.assertGreater(report["coverage"]["expressions_unresolved"], 0)
                if "chr" not in source:
                    self.assertTrue(report["coverage"]["limits_hit"])
        with patch.object(deob, "MAX_OPERATIONS", 15):
            report = self.recover('x="".join(chr(i) for i in [99]*100)')
            self.assertIn("operations", report["coverage"]["limits_hit"])
        with patch.object(deob, "MAX_DECODED_BYTES", 10):
            self.assertIn("decoded_bytes", self.recover('x="hello"')["coverage"]["limits_hit"])
        with patch.object(deob, "MAX_NODES", 3):
            self.assertIn("ast_nodes", self.recover('x=1+2')["coverage"]["limits_hit"])
        with patch.object(deob, "MAX_SOURCE", 3):
            self.assertIn("source_length", self.recover('x=100')["coverage"]["limits_hit"])
        with patch.object(deob, "MAX_RECURSION_DEPTH", 2):
            self.assertIn("expression_depth", self.recover('x=1+(2+(3+4))')["coverage"]["limits_hit"])
        with patch.object(deob, "MAX_FACTS", 2):
            self.assertIn("report_facts", self.recover('x="a"; x="b"; x="c"')["coverage"]["limits_hit"])

    def test_nested_collections_and_unsupported_operations_are_unresolved(self):
        for source in ('x=((1,),)*2000; y={x}', 'x=unknown()', 'x=2**999999999',
                       'x=f"{1:999999999}"', 'x=bytes(999999999)',
                       'x="".join(chr(i) for i in range(999999999))',
                       'x=base64.b64decode("bad padding")'):
            with self.subTest(source=source):
                self.assertGreater(self.recover(source)["coverage"]["expressions_unresolved"], 0)

    def test_malformed_input(self):
        for source in ('if:', b'\xff', '('*1000+'1'+')'*1000, 'x="\x00"'):
            report = self.recover(source)
            self.assertFalse(report["coverage"]["ast_parsed"])
            self.assertTrue(report["diagnostics"])

    def test_never_executes_target(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            payload = f'open({str(marker)!r}, "w").write("bad")'
            report = self.recover(f'import pickle\nimport subprocess\nexec({payload!r})\neval({payload!r})\ncompile({payload!r},"x","exec")\npickle.loads(b"bad")\nsubprocess.run(["touch",{str(marker)!r}])')
            self.assertFalse(marker.exists())
            self.assertGreater(report["coverage"]["expressions_unresolved"], 0)
        tree = ast.parse(Path(deob.__file__).read_text())
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile", "__import__"} for node in ast.walk(tree)))

    def test_truncated_diagnostics(self):
        report = self.recover('x="a"*1000')
        self.assertTrue(any(s["truncated"] for s in report["decoded_strings"]))
        self.assertTrue(all(len(s["value"]) <= 500 for s in report["decoded_strings"]))

    def test_analyzer_correlates_only_called_capabilities(self):
        source = b'''import base64
m=__import__(base64.b64decode("c3VicHJvY2Vzcw==").decode())
f=getattr(m,"".join(chr(i) for i in [80,111,112,101,110]))
f("powershell -enc synthetic")
'''
        report = inspect_python(source, "synthetic.py")
        self.assertIn("subprocess.Popen", report["calls"])
        self.assertIn("suspicious_shell", [f["id"] for f in report["findings"]])
        self.assertIn("deobfuscation", report)
        self.assertEqual(report["unresolved_dynamic_imports"], [])
        self.assertNotIn("obfuscated_runtime_resolution", [f["id"] for f in report["findings"]])
        report = inspect_python(source.replace(b'f("powershell -enc synthetic")', b'x="powershell -enc synthetic"'), "synthetic.py")
        self.assertNotIn("suspicious_shell", [f["id"] for f in report["findings"]])

    def test_browser_path_hint_has_no_verdict(self):
        path = r"Google\Chrome\User Data\Default\Login Data"
        encoded = base64.b64encode(path.encode()).decode()
        report = self.recover(f'x=base64.b64decode({encoded!r}).decode()')
        self.assertIn(path, report["behavior_hints"]["browser_data"])


if __name__ == "__main__":
    unittest.main()
