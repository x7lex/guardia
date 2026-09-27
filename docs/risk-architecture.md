# Conservative deterministic scoring (model 4)

The score is the rounded sum of explained contributions, clamped to 0.0–10.0.
It is a static risk assessment, not a probability or proof of malware. Model 4
replaces the former role/confidence/visibility-floor scoring architecture. Existing
extraction and recovered-script evidence are retained. Old reports remain readable.

## Signature policy

| Signature state | Baseline | Weak/moderate multiplier | Strong-chain multiplier |
| --- | ---: | ---: | ---: |
| Unsigned | 4.0 | 1.5 | 1.5 |
| Invalid/broken integrity | 5.0 | 1.5 | 1.5 |
| Unknown verification | 3.0 | 1.0 | 1.0 |
| Valid, unrecognized issuer | 0.5 | 0.8 | 1.0 |
| Valid, recognized issuer | 0.0 | 0.1 | 1.0 |

The analyzer previously emitted `known_ca: false` unconditionally. It now uses an
explicit code-signing issuer CN list in `src/backend/signatures.py`. The scorer
reuses `known_ca` and can recognize issuer fields in archived reports. A publisher
subject such as Google LLC does not qualify by itself. Invalid or unknown integrity
never receives the trusted discount. This recognition is a deterministic scoring
policy, not a claim of OS trust-store chain validation or checked revocation.

## Contributions

- Isolated suspicious imports add no points. Co-occurring crypto/credential,
  networking, and system/process categories contribute 1.5 for two categories or
  3.0 for all three. JSON includes the matching API names and category evidence.
- Existing stronger behavior rules remain: full process injection requires process
  access, remote allocation, write and execution (6.0); browser credential access
  requires browser profile/storage, reading and decryption (6.0); outbound submission
  with that credential chain adds exfiltration (4.0). WinHttpSendRequest is included.
  These strong rules retain their weight even with trusted signing.
- The strongest adjusted finding per behavioral family contributes; repeated and
  equivalent findings across recovered layers cannot inflate the same family.
- Two active behavioral families multiply their contributions by 1.25; three or
  more use 1.5. Signature baseline and CPU points are excluded from this multiplier.
- CPU groups (discovery/timing, system transition, privileged instructions) add
  0.25 each, capped at 0.75 before signing discounts. Repetition adds nothing;
  ordinary mov/add/xor and compiler padding int3 add nothing. CPU alone cannot
  elevate an unsigned baseline to High Risk.
- Packing, opaque bytes and extraction limits stay informational. They do not
  create hidden score floors or automatic verdict overrides.

Each `reasons` entry gives evidence, nominal points, signature factor, category
factor and final contribution. Deduplicated and informational entries explicitly
contribute zero. `diagnostics.uncapped_score` and the final formula make the score
reconstructable. Thresholds are Low Risk below 4, Suspicious below 6, High Risk
below 8, and Dangerous at 8 or above.

Examples: unsigned crypto + network + process imports score 8.5; the same broad
capabilities with trusted signing score 0.3. A complete injection chain remains at
least 6.0 with trusted signing. Credential access plus submission can reach 10.0
regardless of signing. This distinguishes common capability overlap from stronger
combinations without making signing an absolute exemption.

## Gemini second opinion

API scans, CLI scans/rescores and the comparison script send raw analysis plus
its deterministic assessment to Gemini after scoring. The prompt requests plain
text paragraphs addressing score reasonableness, likely false positives and false
negatives, and concise reasoning. Embedded evidence is explicitly untrusted.
The response is saved separately in `gemini_review`; it never overwrites the score.
Provider failures, absent credentials and the 4 MiB size limit produce an explicit
unavailable review while preserving the complete deterministic report. Reviews
are not silently truncated. The existing manual endpoint allows retry.

## Fixture results and limits

All three available original executables were parsed statically, never executed.
Both saved analysis and fresh scans received live Gemini reviews. Reports are in
`docs/diagnostics/model4` alongside the comparison JSON.

| Fixture | Fresh score | Interpretation |
| --- | ---: | --- |
| ChromeSetup.exe | 0.6 | Valid recognized DigiCert signature heavily discounts common installer capabilities. |
| hrisitosense.exe (cheat) | 4.0 | Unsigned baseline; UPX obscures most imports. Packing alone is not proof of malicious behavior. |
| pip/distlib t64.exe launcher | 4.0 | Benign unsigned software still receives the conservative review baseline. |
| legacy_malware.exe | 4.5 | Unsigned baseline plus 0.5 CPU points; the obfuscated payload remains only partially recovered. |

The known malware is an acknowledged false negative for High Risk classification:
its extracted evidence does not expose the required malicious combinations. Gemini
also identified this limitation. Its ground-truth label is not fed into scoring,
and the scorer does not manufacture behavior from filenames, packing, or labels.
Expanding payload recovery is separate from this scoring redesign. The simple
unsigned baseline ensures this file is still flagged Suspicious, not Low Risk.

Regression tests cover isolated APIs, pair/triple combinations, trusted versus
unrecognized signing, invalid signatures, strong-chain overrides, issuer spoof
names, family amplification/deduplication, CPU repetition/caps, identity invariance,
score reconstruction, and Gemini failure/score preservation. Browser tests verify
new score presentation, attached reviews and manual retries on isolated ports.
