import os
import json
import hashlib
from pathlib import Path

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

SUSPICIOUS_INSTRUCTIONS = {
    "syscall",
    "sysenter",
    "int",
    "rdtsc",
    "rdtscp",
    "cpuid",
    "hlt",
    "in",
    "out",
}

# this is example, user input will be needed
TARGET_FILE = Path("hrisitosense.exe")
BINARY = lief.parse(str(TARGET_FILE))

def get_sha256() -> str:
    sha256 = hashlib.sha256()

    with TARGET_FILE.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()

def get_imports() -> dict:
    libraries = []
    total_functions = 0

    for imported_lib in BINARY.imports:
        functions = []

        for entry in imported_lib.entries:
            if entry.name:
                functions.append(entry.name)
            else:
                # winapi uses ordinals too
                functions.append(f"Ordinal {entry.ordinal}" if os.name == "nt" else "")

        total_functions += len(functions)

        libraries.append({
            "name": imported_lib.name,
            "functions": functions,
        })

    return {
        "library_count": len(libraries),
        "function_count": total_functions,
        "libraries": libraries,
    }

def get_info() -> dict:
    sections = []

    for section in BINARY.sections:
        sections.append({
            "name": section.name,
            "virtual_address": hex(section.virtual_address),
            "virtual_size": section.virtual_size,
            "raw_size": section.size,
            "entropy": round(section.entropy, 2),
            "executable": section.has_characteristic(
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
            ),
        })

    return {
        "file_name": TARGET_FILE.name,
        "file_size": TARGET_FILE.stat().st_size,
        "sha256": get_sha256(),
        "format": str(BINARY.format),
        "machine": str(BINARY.header.machine),
        "entry_point": hex(BINARY.entrypoint),
        "section_count": len(BINARY.sections),
        "sections": sections,
    }

def get_signatures() -> dict:
    known_issuers = [
        "DigiCert",
        "Sectigo",
        "GlobalSign",
        "Entrust",
        "GoDaddy",
        "SSL.com",
        "IdenTrust",
        "Certum",
        "SwissSign",
        "Trustwave",
        "QuoVadis",
        "HARICA",
        "Actalis",
        "Buypass",
        "Telia",
        "Microsoft",
        "Apple",
        "Google",
    ]

    if not BINARY.has_signatures:
        return {
            "signed": False,
            "integrity": "UNSIGNED",
            "known_ca": False,
        }

    integrity_valid = False
    known_ca_found = False

    for signature in BINARY.signatures:
        result = signature.check()

        if result == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            integrity_valid = True

        for cert in signature.certificates:
            if any(
                ca.lower() in cert.issuer.lower()
                for ca in known_issuers
            ):
                known_ca_found = True

    return {
        "signed": True,
        "integrity": "VALID" if integrity_valid else "INVALID",
        "known_ca": known_ca_found,
    }

# ai generated
def get_suspicious_instructions() -> dict:
    mode = (
        CS_MODE_64
        if BINARY.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
        else CS_MODE_32
    )

    disassembler = Cs(CS_ARCH_X86, mode)

    found = []

    for section in BINARY.sections:
        if not section.has_characteristic(
            lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
        ):
            continue

        code = bytes(section.content)

        for instruction in disassembler.disasm(
            code,
            section.virtual_address
        ):
            if instruction.mnemonic in SUSPICIOUS_INSTRUCTIONS:
                found.append(instruction.mnemonic)

    return {
        "count": len(found),
        "instructions": sorted(set(found)),
    }

def output() -> dict:
    report = {
        "file": get_info(),
        "imports": get_imports(),
        "signature": get_signatures(),
        "suspicious_instructions": get_suspicious_instructions(),
    }

    return report
