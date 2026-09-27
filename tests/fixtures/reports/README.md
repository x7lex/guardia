# Complete diagnostic reports

These files are unchanged copies of the supplied schema-2.2 reports under
`src/reports/stuff_2026-09-27_04-23-17_907694`:

- `installer.json`: ChromeSetup.exe, legitimate installer.
- `packed_application.json`: hrisitosense.exe, CSGO cheat; risky/opaque is not proof of malware.
- `opaque_container.json`: legacy_malware.exe, known malware in the supplied ground truth.

Names and labels select fixtures only. The classifier does not consult this folder
or use sample identities. Tests mutate identities and assert combination/signature scoring
invariants. No binaries are stored or executed by tests.
