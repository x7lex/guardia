# Evidence, reputation and independent Gemini analysis (model 5)

Model 5 keeps three distinct mechanisms in each report: `reputation`,
`risk_assessment`, and `gemini_review`. It replaces the model 4 policy; historical
reports under `docs/diagnostics/model4` are retained as comparisons.

## What was wrong with model 4

1. The hash was calculated but never checked. A known malware sample could receive
   a low score if its visible loader exposed few behavioral clues.
2. Packing, writable executable sections and concealed script imports were
   effectively free. The obfuscated malware fixture scored 4.5 almost entirely
   because it was unsigned, even though concealment evidence was present.
3. Conversely, broad crypto/network/process API combinations had too much weight.
   They describe ordinary installers, browsers and security software too.
4. The full injection capability chain carried six nominal points, implicitly
   over-equating injection with malicious intent. Cheats and debugging tools are
   a difficult counterexample; static imports do not prove intent or execution.
5. Issuer-name recognition was labeled trusted signing despite no OS trust-store
   validation. Model 5 explicitly distinguishes recognition from verified chains.
6. The old cross-family multiplier could amplify overlapping observations of the
   same behavior. Model 5 deduplicates families and groups correlated structures.
7. Gemini was asked whether the score was reasonable. That made it a score reviewer,
   not an independent assessment of the underlying evidence.

## A. Reputation: an explicit decision after local scoring

Configuration defaults to `REPUTATION_PROVIDER=disabled`. Choose `malwarebazaar`
with `MALWAREBAZAAR_API_KEY`, or `virustotal` with `VIRUSTOTAL_API_KEY`. Credentials
remain on the backend. Both adapters have a 15-second overall timeout and do not
follow redirects. They send only SHA-256. There is no binary-upload or download
implementation, even for unknown hashes.

MalwareBazaar uses its authenticated `get_info` hash query. A successful response
must contain the exact requested SHA-256 in its malware collection. A not-found
response means unknown, not clean. This follows the provider's
[hash-query API](https://bazaar.abuse.ch/api/), whose submission policy is for
confirmed malware.

VirusTotal retrieves the existing [file object by hash](https://docs.virustotal.com/reference/files).
The following thresholds are our conservative policy, not guarantees made by
VirusTotal:

- Known malicious: at least 10 malicious engine verdicts and at least 25% of
  completed verdicts are malicious. Sparse detections do not activate an override.
  A provider summary category/label identifying hacktool, riskware, PUA/PUP, adware
  or cheat also prevents this override; dual-use reputation remains separately visible.
- Reputable: at least 20 completed verdicts, no malicious or suspicious verdicts,
  community reputation at least 100, at least 10 harmless community votes, and
  no malicious community votes. This is corroborated positive reputation, not
  certified cleanliness. Non-detection alone is unknown.
- Otherwise: unknown. Provider identity/hash mismatches and malformed responses
  are unavailable. Authentication errors, outages, disabled service and rate limits
  remain explicit states and never discard the static report.

A normalized exact known-malicious match sets the final engine score to 10.0 and
`risk.classification=known_malicious`, with `decision.source=reputation_override`.
The original `heuristic.points` and all local contributions remain visible. The
signature does not participate in this decision. This is not an additive bonus.

Positive reputation halves weak-finding contributions and credits 2.0 points
against an unsigned baseline, after local scoring and before clamping. An otherwise
ordinary reputable unsigned file can therefore score 2.0. It cannot reduce an
invalid signature baseline, moderate or strong evidence, or any known-malicious override. It cannot create an unconditional
safe verdict. Reputation evidence and the explicit deduction are shown separately.

Reputation is external intelligence, not infallible ground truth. Provider errors,
false-positive engine consensus and outdated records remain possible. The report
retains the provider, lookup time, exact hash and decision evidence for review.

## B. Deterministic analysis

The local score is the sum of explained contributions, clamped to 0–10 and rounded
to one decimal. It is neither a probability nor a confirmed malware diagnosis.
Unsigned alone remains 4.0: a review signal. Multiple suspicious characteristics
escalate much faster for unsigned files than for signed software.

### Signature baseline and evidence multipliers

| Signature state                         | Baseline | Weak | Moderate | Strong |
| --------------------------------------- | -------: | ---: | -------: | -----: |
| Unsigned                                |      4.0 |  1.5 |     1.75 |    1.5 |
| Invalid or revoked                      |      5.0 |  1.5 |     1.75 |    1.5 |
| Unknown verification                    |      3.0 |  1.0 |      1.0 |    1.0 |
| Valid integrity, unrecognized issuer    |      0.5 | 0.75 |      1.0 |    1.0 |
| Valid integrity, recognized issuer      |      0.0 |  0.2 |      0.6 |    1.0 |
| Valid integrity, verified trusted chain |      0.0 |  0.1 |      0.5 |    1.0 |

The current cross-platform analyzer verifies embedded signature integrity and
recognizes explicit issuer CNs. It does not validate against an OS root store or
check revocation online. Thus Chrome is `recognized_signed`, not falsely reported
as fully chain-verified. A supplied explicit trusted-chain result receives the
stronger weak-signal discount. Revoked/invalid evidence takes precedence.

### Nominal findings (before multipliers)

| Evidence                                                            |           Points | Strength / rationale                                     |
| ------------------------------------------------------------------- | ---------------: | -------------------------------------------------------- |
| Isolated suspicious API, URLs/domains/cookie words, debugger API    |                0 | Generic capability or unlinked text                      |
| Two / three crypto-network-process import categories                |        0.5 / 1.0 | Weak; breadth is common in legitimate software           |
| Full process-access/allocation/write/execution chain                |              3.0 | Specific but dual-use; signature multiplier fixed at 1.0 |
| Browser profile + credential store + file read + decrypt            |              5.0 | Strong correlated credential-access evidence             |
| Credential chain + outbound submission                              |              8.0 | Strong; supersedes the credential-access finding         |
| Autorun or startup target plus writing                              |             0.75 | Weak; target linkage is not proven                       |
| Service persistence / scheduled execution / concealed shell command |              2.0 | Moderate                                                 |
| Download, file-write and launch capability                          |              0.5 | Weak; expected in installers                             |
| Explicit script download-and-evaluate execution sink                |              4.0 | Strong                                                   |
| Multiple anti-analysis checks / VM discovery chain                  |       0.5 / 0.25 | Weak                                                     |
| Encoded script execution or concealed runtime import resolution     |             1.25 | Moderate; also occurs in protectors                      |
| Packer sections / high-entropy executable section alone             |       1.0 / 0.25 | Weak; strongest concealment finding only                 |
| Majority opaque appended payload                                    |             0.75 | Weak; only if incompletely inspected                     |
| Writable executable section                                         |             0.35 | Weak; also used by JITs/unpackers                        |
| Out-of-bounds sections or inconsistent entry/header ranges          |              1.0 | Moderate structural inconsistency                        |
| CPU discovery/timing / system transition / privileged group         | 0.1 / 0.1 / 0.25 | Weak; capped at 0.5 nominal                              |
| Generic local YARA match                                            |              0.5 | Weak, not automatically malware                          |
| Explicit high-confidence malware YARA rule                          |              8.0 | Strong; no signature discount                            |

CPU repetition never increases weight. Common mov/add/xor and int3 padding are
not scored. COFF timestamp and PE header values are retained as raw metadata;
a zero or unusual timestamp by itself is not evidence of malware.

YARA inspection is optional (`yara-python` is already in `requirements.txt`).
Set `YARA_RULES_PATH` to a
local UTF-8 rule file. Include directives are disabled and matching has a five-second
timeout. No rules are fetched. For strong weight, a reviewed local rule must have
`malware = true` and `confidence = "high"` metadata; otherwise the match is weak.
Reports retain the rule-file SHA-256 and matching rule metadata. Configuring a bad
rule can cause false positives; metadata is the operator's explicit specificity
claim, not a claim inferred from a rule name. Missing dependencies, invalid rules
and timeouts remain nonfatal. The optional API usage follows the
[YARA Python documentation](https://yara.readthedocs.io/en/latest/yarapython.html).

### Deduplication and correlations

Only the strongest adjusted finding in each family contributes, including across
recovered script layers. Credential exfiltration and credential access share one
family. Packer layout, entropy, opaque payloads and script concealment share another.
Informational and superseded findings remain in JSON with zero contribution.

Cross-domain amplification uses distinct behavior, structure/concealment, CPU,
and specific-YARA domains. Import combinations and behavioral chains count as one
behavior domain; packing and RWX do not pretend to be independent domains.
The injection chain uses a signature multiplier of 1.0 for all signature states:
the unsigned baseline already differentiates it, and injection alone stays below
Dangerous (7.0 unsigned, 3.0 recognized-signed). Additional independent evidence
can still amplify it. A single common CPU group does not activate correlation; two groups or a privileged
group can. A generic YARA match also cannot activate correlation.

- Unsigned/invalid: two domains multiply contributing findings by 1.25; three or
  more multiply them by 1.5.
- Other signature states: the equivalent factors are 1.1 and 1.2.
- Two or more independent behavioral families additionally multiply behavioral
  findings by 1.25. Generic import categories are not a second behavioral family.
- The signature baseline is never amplified.

Every scored row includes nominal points, signature multiplier, correlation
multiplier, final points, and concrete evidence. There is no confidence index,
visibility floor, installer-name exemption, or filename/hash-specific heuristic.

UI faces retain the requested cutoffs: below 3 happy, 3–4.9 neutral, 5+ frowny.
High Risk begins at 5 and Dangerous at 8. Neither heuristic label asserts known
malware; that designation comes from the explicit reputation override.

## C. Independent Gemini analysis

The provider receives exactly `analysis` (all raw evidence) and `reputation`.
The whitelist deliberately excludes `risk_assessment`, weighted reasons, local
verdicts and previous Gemini output. Legacy scoring weights inside recovered script findings
are also removed; their capabilities, strings, sources and other evidence remain. The raw analysis contains signatures/issuers,
PE headers, imports/functions, sections, entropy, instructions/counts, strings,
YARA, resources and recovered scripts. It is not truncated to a summary.
Oversized requests return an explicit unavailable state rather than silently
omitting evidence. Embedded sample text is treated as untrusted input.

The prompt requests independent reasoning from this evidence, permits disagreement,
and prohibits treating unsigned as malicious or signing as safety. The first line
must be exactly one of:

```
THIS IS PERFECTLY FINE
I CANNOT CONFIDENTLY SAY THAT
USE AT YOUR OWN RISK
```

A plain-text explanation must follow. Formatting cleanup remains, but the backend
never manufactures a verdict: an invalid prefix, multiple verdict phrases or an
absent explanation is rejected. Gemini's opinion never modifies either engine score.
A positive Gemini statement is an opinion on available evidence, not a guarantee.
Old cached score-aware reviews are labeled legacy in the UI.

## Calibration and verification

All executables are parsed statically, never run. `docs/diagnostics/model5` contains
full saved-report rescoring, fresh scans and independent Gemini outputs.
The comparison JSON's `old_risk` is the original historical fixture score;
the table below compares against the later model 4 diagnostic reports.

| Fixture                  | Model 4 | Model 5 local score | Why                                                                                                            |
| ------------------------ | ------: | ------------------: | -------------------------------------------------------------------------------------------------------------- |
| ChromeSetup.exe          |     0.6 |                 0.4 | Valid recognized signature and generic installer capability overlap; no specific malicious chain               |
| hrisitosense.exe (cheat) |     4.0 |                 6.0 | Unsigned, UPX layout and writable executable sections; not classified as confirmed malware                     |
| legacy_malware.exe       |     4.5 |                 7.1 | Unsigned, concealed runtime imports and multiple CPU groups correlate; payload remains incompletely understood |

No reputation key is configured in this environment, so these real fixture scores
have reputation disabled. We do not claim a live known-malicious hash hit. Mocked
MalwareBazaar/VirusTotal responses verify the exact-hash override, including a
trusted-signed input with heuristic score zero producing final score ten.
The known malware is now high risk locally, but its harmful payload is still not
fully recovered. Improved triage does not resolve that extraction limitation.

Gemini independently judged Chrome positively and the opaque malware/cheat
ambiguous in successful live evaluations; the full explanations and any transient
provider failures are saved. It was not shown the scores or sample ground-truth
labels. Names only select fixtures; the scorer never consults calibration labels.

Tests cover correlations, common-instruction bounds, Chrome with added generic
capabilities, signed dual-use injection, strong YARA, signature states, exact hash
identity, provider outages/disabled/quota/no record, positive reputation limits,
score reconstruction and unchanged raw Gemini request bodies under opposite local
scores. A synthetic rule was also checked against the real local YARA engine.
Browser tests cover independent-review display and separate heuristic/reputation
scores. See README for reproduction commands and optional configuration.
