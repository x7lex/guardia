# Static triage model 3.0

This redesign was driven by the **complete** three supplied JSON reports, not by
filename or hash rules. They are a diagnostic set, not enough data to calibrate a
malware probability or validate real-world detection performance. Ground truth is
used in tests/documentation only. No classifier rule examines the input filename,
hash, or a publisher allowlist.

## What the original reports establish

| Property | Known malware | CSGO cheat | Chrome installer |
| --- | --- | --- | --- |
| Previous score | 1.5 | 2.0 | 2.5 |
| Named imports | 112 | 11 | 425 |
| Appended non-certificate bytes | 12,850,547 (96.88%) | 0 | 0 |
| Certificate bytes in overlay | 0 | 0 | 18,872 |
| Key concealment evidence | Partial ZIP inspection; encoded Python imports; native/bytecode members | UPX0/UPX1, RWX, UPX1 entropy 7.744, sparse loader imports | No native packer layout in saved facts |
| Signature | Unsigned | Unsigned | Integrity VALID; Google LLC subject, chain NOT_EVALUATED, revocation NOT_CHECKED |
| Specific recovered malicious chain | None established | None established | None established |

Chrome's two browser database string matches, 66 URL matches, 62 domain matches,
and 425 imports are **not** malicious evidence. All three have dynamic resolution
capability. A bare debugger API, generic process query or linear-disassembly
instruction count likewise establishes little. The original autorun rule did not
prove that registry writes targeted the matched key, and ignored installer role.

The original packing-family score discarded the *meaning* of multiple visibility
limitations. Changing their weights would not fix this. Also, an inspection that
read every compressed byte was still only a **partial semantic analysis**: native
members and custom script decoding remained unresolved.

## Separate assessments

1. **Threat evidence:** source-local behavioral correlations. Injection requires
   access + remote allocation + write + execution. Browser credential access needs
   profile + storage + reads + decryption. Outbound submission strengthens that
   same credential chain. Download/execute needs retrieval + write + launch.
   Service persistence needs creation/configuration and suspicious path context.
   Weak administrative co-occurrence is clearly identified as unlinked.
2. **Visibility:** a heuristic index with GOOD, PARTIAL and SEVERELY_LIMITED levels.
   Each concrete extraction gap specifies a ceiling, and the lowest applies.
   This avoids treating correlated packer clues as independent penalties. The
   baseline is 0.90, never FULL: this scanner has no complete control-flow analysis.
3. **Trust:** signature integrity, certificate subject, chain trust, publisher
   identity verification and revocation remain separate. `known_ca` or an issuer's
   name cannot establish publisher trust. Signing is never a flat score discount.
4. **Context:** installer/updater, packed application, container application,
   library or unknown. Installer role needs several independent clues (version
   descriptions or installation vocabulary, service lifecycle, and file/process/
   registry capabilities). A signed metadata match helps confidence in the claimed
   role, not verification of the publisher. No filename or Google-domain whitelist.

The shared behavior engine is used for the native PE and each recovered script
member/layer. It never combines imports from unrelated bundled runtime libraries.
Equivalent behaviors are deduplicated by a maximum within each threat family;
family caps and the selected contribution remain visible in `reasons` and
`diagnostics.family_scores`. Packing/entropy/RWX and unresolved names contribute
**zero threat points**, but can sharply limit visibility.

Installer adjustment applies only to ambiguous **outer-PE** behavior: autorun
co-occurrence, startup writes, ordinary service installation and download/launch.
The factor is 0.5 with inferred installer context, or 0.25 when signature integrity
also protects that metadata. It does not affect injection, credential chains,
exfiltration, suspicious service paths, or findings in bundled scripts.

## Final score and verdict

All scores are transparent triage weights, not probabilities:

```text
threat = round(min(10, sum(family_scores)), 1)
review_floor = round(min(3.5, 4 * (1 - visibility)), 1) if visibility < 0.75 else 0
triage = max(threat, review_floor)
uncertainty_contribution = triage - threat
```

Risk bands are Low Risk (<4), Suspicious (4–<6), High Risk (6–<8), Dangerous (8–10).
An independent **Inconclusive verdict** applies when visibility is below 0.75 and
threat evidence is below 6. Strong evidence retains High Risk/Dangerous even with
poor visibility; the visibility limitation remains visible. Uncertainty alone
cannot reach High Risk. The UI uses `risk.verdict` before `risk.level` when grouping
reports. This avoids a low numeric score placing an opaque file in the benign group.

`risk.confidence` repeats the visibility index for compatibility with the requested
shape. Its meaning is explicit: it is not calibrated confidence in a verdict or a
measured percentage of code examined. Low Risk is not a guarantee of safety.

## Extraction changes

- Preserved LIEF signature checks, SHA-256, import/section extraction, bounded
  string matching and informational Capstone decoding.
- Inventoried version metadata and resource leaves, with node/leaf/byte limits.
  Packed resources and embedded native candidates get explicit coverage gaps.
- Split overlay inspection into non-certificate ranges, including bytes **after**
  a certificate table. Invalid claimed certificate ranges are not subtracted.
  The certificate table uses a file offset, as specified in the
  [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
  Resource extraction follows [LIEF's resource model](https://lief.re/doc/latest/tutorials/07_pe_resource.html).
- ZIP reports distinguish source, native, bytecode and other uninspected members.
  They record sizes, member statuses, decoded layers and nested archive limits.
  Source-only archives can complete inspection; other members retain limitations.
- Expanded AST-only literal recovery to strings/bytes, concatenation, bounded
  character construction, literal joins, slices/reversal, hex text, encoded
  attribute lookup, dynamic literal imports and narrow XOR templates. Kept the
  bounded base64/compression decoder for execution inputs. Name resolution is
  position-aware and conservative across branches, parameter shadowing and
  reassignment. No target-defined function or recovered source is executed.

## Results and remaining limits

| Input facts | Threat | Triage | Verdict | Visibility |
| --- | ---: | ---: | --- | --- |
| Saved malware report | 0.0 | 3.2 | Inconclusive | SEVERELY_LIMITED (0.20) |
| Saved cheat report | 0.0 | 3.2 | Inconclusive | SEVERELY_LIMITED (0.20) |
| Saved Chrome report | 0.6 | 0.6 | Low Risk | GOOD (0.80) |
| Fresh malware scan | 0.0 | 3.2 | Inconclusive | SEVERELY_LIMITED (0.20) |
| Fresh cheat scan | 0.0 | 3.2 | Inconclusive | SEVERELY_LIMITED (0.20) |
| Fresh Chrome scan | 0.6 | 1.8 | Inconclusive | PARTIAL (0.55) |

These values are observed results, not regression targets. Tests assert invariants,
including stability when sample names/hashes/publisher names are changed.

The fresh Chrome scan finds version metadata identifying an installer **and a
7,401,066-byte embedded 7z resource** omitted by the old report. This legitimately
lowers visibility without adding malicious evidence. Ground-truth legitimacy must
not cause a classifier to pretend unexamined content was inspected.

The known malware's custom obfuscation still hides its deeper capabilities. The
new decoder recovers common literal transformations but intentionally does not run
arbitrary decoder functions or solve arbitrary encrypted programs. Its result is
therefore Inconclusive, not a fabricated credential-theft or injection finding.
UPX native unpacking, 7z expansion, semantic native archive-member analysis,
bytecode interpretation, CFG/data-flow recovery, chain validation and revocation
checks remain unimplemented and are disclosed. Three profiles do not validate the
chosen weights on general software populations.

Complete old fixtures live in `tests/fixtures/reports`. Complete rescored and fresh
reports plus the machine-readable comparison live in `docs/diagnostics`.
Reproduce the saved-report comparison without binaries:

```sh
.venv/bin/python scripts/compare_reports.py
```

To also perform static rescans, pass `--samples-dir /path/to/original/files`.
The command reads the PE files; it does not execute them or any recovered payload.
