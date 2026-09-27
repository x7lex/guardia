"""Static analysis of Windows PE files (the target is never executed)."""

import asyncio
import hashlib
from pathlib import Path

import capstone
import lief

SUSPICIOUS_INSTRUCTIONS = {
    "in",
    "insb",
    "insd",
    "insw",
    "out",
    "outsb",
    "outsd",
    "outsw",
    "int",
    "int1",
    "int3",
    "syscall",
    "sysenter",
    "rdmsr",
    "wrmsr",
    "rdtsc",
    "rdtscp",
    "cpuid",
    "hlt",
    "cli",
    "sti",
}


def _analyze(target_file: Path) -> dict:
    path = target_file.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")

    # Hash in chunks so large files don't require another full copy in memory.
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)

    binary = lief.PE.parse(str(path))
    if binary is None:
        raise ValueError(
            f"Unsupported or invalid file: {path.name}. Expected a Windows PE executable or DLL."
        )

    sections = []
    for section in binary.sections:
        sections.append(
            {
                "name": section.name,
                "virtual_address": hex(section.virtual_address),
                "virtual_size": section.virtual_size,
                "raw_size": section.sizeof_raw_data,
                "entropy": round(section.entropy, 2),
                "executable": section.has_characteristic(
                    lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
                ),
            }
        )

    libraries = [
        {
            "name": library.name,
            "functions": [
                f"ordinal:{entry.ordinal}" if entry.is_ordinal else entry.name
                for entry in library.entries
            ],
        }
        for library in binary.imports
    ]

    signed = binary.has_signatures
    integrity = "UNSIGNED"
    if signed:
        verification = binary.verify_signature()
        integrity = (
            "VALID"
            if verification == lief.PE.Signature.VERIFICATION_FLAGS.OK
            else str(verification)
        )

    machine = binary.header.machine
    modes = {
        lief.PE.Header.MACHINE_TYPES.I386: capstone.CS_MODE_32,
        lief.PE.Header.MACHINE_TYPES.AMD64: capstone.CS_MODE_64,
    }
    suspicious = set()
    if machine in modes:
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, modes[machine])
        disassembler.skipdata = True
        for section, metadata in zip(binary.sections, sections):
            if not metadata["executable"]:
                continue
            for _, _, mnemonic, _ in disassembler.disasm_lite(
                bytes(section.content),
                binary.optional_header.imagebase + section.virtual_address,
            ):
                if mnemonic in SUSPICIOUS_INSTRUCTIONS:
                    suspicious.add(mnemonic)

    return {
        "file": {
            "file_name": path.name,
            "file_path": str(path),
            "file_size": path.stat().st_size,
            "sha256": digest.hexdigest(),
            "format": str(binary.format),
            "machine": str(machine),
            "entry_point": hex(binary.entrypoint),
            "section_count": len(sections),
            "sections": sections,
        },
        "imports": {
            "library_count": len(libraries),
            "function_count": sum(len(item["functions"]) for item in libraries),
            "libraries": libraries,
        },
        "signature": {
            "signed": signed,
            "integrity": integrity,
            # Integrity verification alone does not establish CA trust.
            "known_ca": False,
        },
        "suspicious_instructions": {
            "count": len(suspicious),
            "instructions": sorted(suspicious),
            "supported": machine in modes,
        },
    }


async def output(target_file: Path | str) -> dict:
    """Return a JSON-serializable report without blocking the async scanner."""
    return await asyncio.to_thread(_analyze, Path(target_file))
