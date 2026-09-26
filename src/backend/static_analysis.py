"""a"""
import os
import lief
#import json
from pathlib import Path
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

# this will be based on userinput on the web soon
def get_file(target_file: Path) -> str:
    return str(target_file)

BINARY = lief.parse(get_file('hrisitosense.exe'))


"""a"""
def get_imports() -> str:
    for imported_lib in BINARY.imports:
        print(f'\nLibrary: {imported_lib.name}')

        for entry in imported_lib.entries:
            if entry.name:
                print(f'Function: {entry.name}')
            else:
                # windows uses ordinals
                print(f'Ordinal {entry.ordinal}' if os.name == 'nt' else '')


def get_info() -> str:
    print(f"Format:      {BINARY.format}")
    print(f"Entry Point: {hex(BINARY.entrypoint)}")
    print(f"Machine:     {BINARY.header.machine}")

    print("\nSections:")
    for section in BINARY.sections:
        print(
            f"  {section.name:<10} "
            f"VA={hex(section.virtual_address):<12} "
            f"Entropy={section.entropy:.2f}"
        )

def get_signatures() -> None:
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

        # Major platform/vendor PKI
        "Microsoft",
        "Apple",
        "Google",
    ]

    if not BINARY.has_signatures:
        print("Signature: UNSIGNED")
        return

    for i, signature in enumerate(BINARY.signatures, start=1):
        print(f"\n--- Signature {i} ---")

        result = signature.check()

        if result == lief.PE.Signature.VERIFICATION_FLAGS.OK:
            print("Integrity: VALID")
        else:
            print(f"Integrity: INVALID ({result})")

        known_ca_found = False

        for cert in signature.certificates:
            print(f"\nSubject: {cert.subject}")
            print(f"Issuer:  {cert.issuer}")

            if any(ca.lower() in cert.issuer.lower() for ca in known_issuers):
                print("Issuer: KNOWN")
                known_ca_found = True
            else:
                print("Issuer: UNKNOWN")

        # only part that really matters
        print("\nSummary:")

        # refer to the point system on google docs
        # known/unknown 
        print(f"Integrity: {'VALID' if result == lief.PE.Signature.VERIFICATION_FLAGS.OK else 'INVALID'}")

        # good/bad 
        print(f"Known CA present: {'YES' if known_ca_found else 'NO'}") 

def get_suspicious_instructions() -> tuple[int, list[str]]:
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

    return len(found), sorted(set(found))

print(get_suspicious_instructions())