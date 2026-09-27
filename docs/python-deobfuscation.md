# Static Python deobfuscation

`backend.deobfuscator.analyze_python_source(source)` accepts Python text or source
bytes and returns JSON-compatible facts. It requires only the standard library.
It neither classifies malware nor assigns risk points.

```python
from backend.deobfuscator import analyze_python_source

facts = analyze_python_source('''
import base64
module = __import__(base64.b64decode("c3VicHJvY2Vzcw==").decode())
launch = getattr(module, "".join(chr(i) for i in [80, 111, 112, 101, 110]))
launch("powershell -enc synthetic")
''')
```

The result includes a dynamically resolved `subprocess` import, a `Popen`
attribute on `subprocess`, and a `subprocess.Popen` call. Looking up the attribute
without calling it produces attribute evidence only. All facts describe source
syntax and potential capabilities; they do not prove reachability or execution.

## Integration

The existing path is `analyzer.py → payloads.py → scripts.inspect_python`.
Each recovered source member or decoded layer now has a `deobfuscation` object
alongside its existing calls, capabilities, findings and limitations. The helper
also runs on source fragments that fail parsing, returning parse diagnostics.
The PE parser does not import or depend directly on the deobfuscator.

Recovered call names and complete, bounded string examples feed the existing
source-local behavior correlations in `scripts.py`. Imports and attribute hints
alone are not promoted to executed calls. Independently recovered archive members
are not combined into behavior chains. Dynamic import source locations remove
obsolete unresolved-import findings when the new helper resolves those sites.
Limit diagnostics enter the script's existing visibility limitations. Resolution
ratio is reported for inspection, not converted into threat points.

The earlier `script_symbols.py` recovery remains in place for its specialized
XOR-lambda syntax and accumulator patterns. This addition enriches that pipeline;
it does not replace its existing decoding or behavior rules.

## Supported expressions

- Sequential constant assignments and symbolic import/function aliases.
- Strings, bytes, integers, booleans, `None`, and flat lists, tuples, sets and maps.
- Concatenation, bounded repetition, integer arithmetic and bitwise operations.
- Known indices and slices, reversal, and basic constant f-strings without format
  specifications or explicit conversions.
- `chr`, `ord`, integer arrays to bytes, `reversed`, and `map(chr/ord, constants)`.
- One-generator comprehensions over bounded constant sequences, without filters,
  asynchronous iteration or arbitrary function calls.
- Base64 and URL-safe Base64, hexadecimal decoding, literal joins, replacement,
  and encoding/decoding with UTF-8, ASCII, Latin-1 or UTF-16LE.
- Normal imports, `__import__`, `importlib.import_module`, `getattr`, and builtins
  dictionary/namespace lookups, including aliases. These yield symbolic names.
- Composed transformations, including Base64 → hex and Base64 → reversal.

Bare `builtins`, `__builtins__` and `base64` names are recognized in recovered
fragments even if the import statement is missing. An explicit reassignment
invalidates that interpretation. These are static fragment assumptions, not
confirmation that the names have those runtime bindings.

Unknown calls, possible mutations and unsupported statements invalidate propagated
state conservatively. Branches are examined independently without choosing a
runtime alternative. Function bodies are inspected without calling them or
inheriting mutable outer bindings. General loops, exception flow, arbitrary
functions/classes, nested containers and complex formatting stay unresolved.
The conservative invalidation can miss facts after an unknown call.

## Safety and resource bounds

The helper parses with `ast.parse`. It never calls target `eval`, `exec`,
`compile`, imports, functions, constructors, subprocesses, bytecode or pickle
loaders. Pure transformations use explicit handlers on validated local primitives;
method names on unknown objects do not authorize invocation. Codec names are
allowlisted. No network requests or runtime probing occur.

Bounds apply before sequence growth or large shifts. Flat collections avoid
exponentially nested hashing and equality. Aggregate intermediate text is charged
on every evaluation, including repeated references, so the budget is intentionally
conservative.

| Resource                           |                                               Limit |
| ---------------------------------- | --------------------------------------------------: |
| Source length                      |                  1,000,000 bytes or text characters |
| AST nodes                          |                                              50,000 |
| Expression / statement depth       |                                                  24 |
| Evaluation operations              |                                              50,000 |
| Collection entries                 |                                               2,000 |
| Individual string / byte value     |                                              64,000 |
| Aggregate intermediate text budget | 4,000,000 bytes (text charged at 4 bytes/character) |
| Integer size                       |                                            128 bits |
| Each fact collection               |                                                 200 |
| Report example / symbolic name     |                                      500 characters |

Nested decoding shares the expression-depth and operation limits; there is no
unbounded repeat-until-decoded loop. The multiple-layer diagnostic recognizes
nested decoder syntax and reversal around a decoder. Separate assignments can
propagate decoded constants, but that diagnostic does not reconstruct their full
provenance chain. Existing recursive source inspection retains its independent
layer and byte budgets.

The output includes categorized strings, import origins, resolved attributes and
calls, behavior hints, bounded transformation examples, diagnostics, and coverage.
`decoded_strings` includes literal candidates as well as transformed values.
Coverage counts evaluator visits (including repeated reads), not distinct AST
nodes. Limits and unsupported expressions yield partial evidence, not a verdict.
Truncated strings remain visible as examples but do not feed behavior correlations.

Run the synthetic decoding, safety, integration and existing scanner tests with:

```sh
.venv/bin/python -m unittest discover -s tests -v
```
