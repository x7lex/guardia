# Guardia

Guardia is a free and open source project that conducts static analysis on applications, then uses LLM reasoning to classify malware, on-top of a point-based risk assessment.

Because of a point-based system, Guardia has taken a different design philosophy, instead of classifying whether something is malware or not we have divided it into four groups:

- 0-30% Risk: **Safe**
- 31-60% Risk: **Risky**
- 61-80% Risk: **Unsafe**
- 81%+ Risk: **Dangerous**

As technology continues to evolve with the rise of AI, malware has became increasingly more sophisticated overtime, this is an eternal game of cat & mouse as most antimalware/antivirus services run on legacy means of detection.

## Guardia vs Antiviruses

In order to assess the performance of Guardia vs common Antivirus vendors there will be different stages of testing:

- Detection of legacy malware
- Detection of encrypted malware (built to be undetected)
- Assessment of false positives (safe applications but being detected)

## Guardia's Assessment

- **Legacy Malware (Simple Stealer): 3/10 (Use at your own risk)**
  - Because of how the point-based system works, this specific malware isn't doing too much to be flagging, Gemini recommended dynamic analysis after that
- **Encrypted Malware (Simple Stealer): 30% (Use at your own risk)**
  - The deobfuscator is good enough to reveal most of the application as if it were unobfuscated.
- **False Positive Rates: 30% (Use at your own risk)**
  - Context: "hrisitosense.exe" is a CSGO cheat, which tend to have a lot of false positives due to the fact they are designed similarly, but because Guardia doesn't use a black/white classification, it's simply encouraging the user to run at their own risk

## Antivirus Vendor's Assessment (Virustotal)

- **Legacy Malware: 17/70 Positive Detections**
  - [8b4d5221a7848dbc72b4b96bb566caaac12ec4338006bbf7e0b8b32f7f8187c6
    ](https://www.virustotal.com/gui/file/8b4d5221a7848dbc72b4b96bb566caaac12ec4338006bbf7e0b8b32f7f8187c6?nocache=1)

- **Encrypted Malware: 16/70 Positive Detections**
  - [a3d9593d459b8e4004dff22b6d2048100cc912cab37095fda6cff247151cc49f
    ](https://www.virustotal.com/gui/file/a3d9593d459b8e4004dff22b6d2048100cc912cab37095fda6cff247151cc49f?nocache=1)
  - Historically, it's common to see 0/70 detections

- **False Postivie Rates: 26/70 False Detections**
  - [f12316bceefbabe45f8279bd5a9d6e8e815a9f76114097991548ca7e259f6472](https://www.virustotal.com/gui/file/f12316bceefbabe45f8279bd5a9d6e8e815a9f76114097991548ca7e259f6472)
  - Context: "hrisitosense.exe" is a CSGO cheat. Cheats tend to have a lot of false positives due to the fact they are designed similarly to malware, since it's hard to distinguish the two antiviruses commonly flag it.
