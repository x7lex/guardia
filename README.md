# Static PE scanner

Run from the project directory:

```sh
.venv/bin/python src/main.py /path/to/file-or-directory
```

Rescore an existing report without reopening its binary:

```sh
.venv/bin/python src/main.py --rescore-report /path/to/report.json
```

Analysis is static only. Reports are written to `src/reports`.
Low scores mean few detected indicators, not verified safety. Substantial
undecoded appended content or other coverage gaps produce `Use at your own risk`
when the evidence score is below 4. Known signatures do not erase findings.

Appended ZIP containers are inspected in memory with entry, byte, depth and
decompression limits. Python source inspection uses syntax and literal
transformations, including encoded built-in names; it never imports or runs
the bundled application. Native archive members and unresolved script layers
remain coverage limitations. Evidence scores do not quantify that uncertainty.
ZIP handling uses the [Python standard library](https://docs.python.org/3/library/zipfile.html).
