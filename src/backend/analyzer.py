"""Bounded, static-only extraction of Windows PE facts. Never loads target code."""

import asyncio
import hashlib
import re
from pathlib import Path

import capstone
import lief

from backend.features import STRING_PATTERNS
from backend.payloads import inspect_payload

MAX_STRING_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_MATCHES = 20


class UnsupportedFileError(ValueError):
    """Input is not a supported PE or exceeds the scanner's resource limit."""


def extract_strings(data):
    patterns = {key: re.compile(value) for key, value in STRING_PATTERNS.items()}
    matches = {key: [] for key in patterns}
    counts = {key: 0 for key in patterns}
    # Bounded chunks of long printable strings prevent huge report entries.
    for regex, encoding in ((rb"[\x20-\x7e]{5,2048}", "ascii"),
                            (rb"(?:[\x20-\x7e]\x00){5,2048}", "utf-16le")):
        for raw in re.finditer(regex, data):
            value = raw.group().decode(encoding)
            for category, pattern in patterns.items():
                for match in pattern.finditer(value):
                    counts[category] += 1
                    entry = match.group()[:500]
                    if entry not in matches[category] and len(matches[category]) < MAX_MATCHES:
                        matches[category].append(entry)
    return {"matches": matches, "match_counts": counts,
            "limits": {"examples_per_category": MAX_MATCHES, "printable_run_characters": 2048},
            "note": "ASCII and ASCII-range UTF-16LE only; text is untrusted data. URLs/domains/IP-like strings carry no risk by themselves."}


def get_signatures(binary):
    result = {"signed": bool(binary.has_signatures), "integrity": "UNSIGNED",
              "chain_trust": "NOT_EVALUATED", "revocation": "NOT_CHECKED",
              "publisher_identity": "NOT_TRUST_VALIDATED", "publishers": [], "checks": [], "known_ca": False}
    if not binary.has_signatures:
        directory = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
        if directory and directory.size:
            result.update(signed=True, integrity="UNKNOWN")
            result["checks"].append({"error": "Certificate table exists but no signature could be parsed"})
        return result
    flags = lief.PE.Signature.VERIFICATION_FLAGS
    checks = lief.PE.Signature.VERIFICATION_CHECKS
    valid, invalid = False, False
    for signature in binary.signatures:
        try:
            full = binary.verify_signature(signature)
            integrity = binary.verify_signature(signature, checks.SKIP_CERT_TIME)
            digest = binary.verify_signature(signature, checks.HASH_ONLY)
            valid |= integrity == flags.OK
            # Expiration, unsupported algorithms and parser failures are not
            # automatically classified as tampering.
            bad_mask = int(getattr(flags, "BAD_DIGEST", 0)) | int(getattr(flags, "BAD_SIGNATURE", 0))
            invalid |= bool(int(integrity) & bad_mask) or bool(int(digest) & int(getattr(flags, "BAD_DIGEST", 0)))
            result["checks"].append({"full_verification": str(full), "integrity_without_time": str(integrity), "file_digest": str(digest)})
            for signer in signature.signers:
                cert = signer.cert
                if cert is not None:
                    result["publishers"].append({"subject": cert.subject, "issuer": cert.issuer, "serial_number": bytes(cert.serial_number).hex()})
        except Exception as error:
            result["checks"].append({"error": str(error)})
    # Preserve a failing signature even if another embedded signature passes.
    result["integrity"] = "INVALID" if invalid else "VALID" if valid else "UNKNOWN"
    return result


def disassembly_facts(binary):
    modes = {lief.PE.Header.MACHINE_TYPES.I386: capstone.CS_MODE_32,
             lief.PE.Header.MACHINE_TYPES.AMD64: capstone.CS_MODE_64}
    result = {"supported": binary.header.machine in modes, "scored": False,
              "scope": "At most 4096 raw bytes at the entry point; linear decoding is not a control-flow graph",
              "bytes_decoded": 0, "instruction_count": 0, "mnemonic_counts": {}}
    if not result["supported"]:
        return result
    rva = binary.optional_header.addressof_entrypoint
    for section in binary.sections:
        offset = rva - section.virtual_address
        if 0 <= offset < len(section.content) and section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
            disassembler = capstone.Cs(capstone.CS_ARCH_X86, modes[binary.header.machine])
            for _, size, mnemonic, _ in disassembler.disasm_lite(bytes(section.content)[offset:offset + 4096], binary.entrypoint):
                result["bytes_decoded"] += size
                result["instruction_count"] += 1
                result["mnemonic_counts"][mnemonic] = result["mnemonic_counts"].get(mnemonic, 0) + 1
            break
    return result


def _analyze(target_file):
    path = Path(target_file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path}")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise UnsupportedFileError("File exceeds the 512 MiB static parser limit")
    with path.open("rb") as source:
        header = source.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            raise UnsupportedFileError("Not a Windows PE executable/DLL")
        pe_offset = int.from_bytes(header[60:64], "little")
        if pe_offset < 64 or pe_offset > size - 24:
            raise UnsupportedFileError("Invalid PE header offset")
        source.seek(pe_offset)
        if source.read(4) != b"PE\0\0":
            raise UnsupportedFileError("Missing PE signature")
        source.seek(0)
        digest = hashlib.sha256()
        sample = bytearray()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            if len(sample) < MAX_STRING_BYTES:
                sample.extend(chunk[:MAX_STRING_BYTES - len(sample)])
    binary = lief.PE.parse(str(path))
    if binary is None:
        raise UnsupportedFileError("LIEF could not parse PE headers")
    sections = []
    for section in binary.sections:
        sections.append({"name": section.name, "virtual_address": hex(section.virtual_address),
                         "virtual_size": section.virtual_size, "raw_size": section.sizeof_raw_data,
                         "raw_offset": section.pointerto_raw_data, "entropy": round(section.entropy, 3),
                         "executable": section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE),
                         "writable": section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE),
                         "raw_out_of_bounds": bool(section.sizeof_raw_data and section.pointerto_raw_data + section.sizeof_raw_data > size)})
    libraries = []
    limitations = []
    for kind, imports in (("normal", binary.imports), ("delay", binary.delay_imports)):
        for library in imports:
            libraries.append({"name": library.name, "kind": kind,
                              "functions": [f"ordinal:{entry.ordinal}" if entry.is_ordinal else entry.name for entry in library.entries]})
    strings = extract_strings(bytes(sample))
    strings.update(bytes_scanned=len(sample), truncated=size > len(sample))
    if strings["truncated"]:
        limitations.append("String scan limited to first 32 MiB; later strings may be missed.")
    if not libraries:
        limitations.append("No named import tables available; packed or dynamically resolved capabilities may be hidden.")
    signature = get_signatures(binary)
    section_end = max([binary.optional_header.sizeof_headers] + [
        section.pointerto_raw_data + section.sizeof_raw_data
        for section in binary.sections if section.sizeof_raw_data
    ])
    overlay_size = max(0, size - section_end)
    certificate = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
    certificate_bytes = 0
    if certificate and certificate.size:
        # Unlike other data directories, this address is a file offset.
        certificate_bytes = max(0, min(size, certificate.rva + certificate.size) - max(section_end, certificate.rva))
    payload_bytes = max(0, overlay_size - certificate_bytes)
    overlay = {"offset": section_end, "size": overlay_size,
               "certificate_bytes": certificate_bytes, "payload_bytes": payload_bytes,
               "payload_fraction": payload_bytes / size if size else 0,
               "content_analysis": "NOT_PRESENT"}
    payload_inspection = None
    if payload_bytes:
        # Exclude the Authenticode certificate table from container inspection.
        payload_end = certificate.rva if certificate and section_end <= certificate.rva < size else size
        inspected_end = min(payload_end, section_end + MAX_STRING_BYTES)
        if inspected_end <= len(sample):
            payload_data = bytes(sample[section_end:inspected_end])
        else:
            with path.open("rb") as source:
                source.seek(section_end)
                payload_data = source.read(max(0, inspected_end - section_end))
        payload_inspection = inspect_payload(payload_data, section_end)
        overlay["content_analysis"] = "BOUNDED_STATIC_CONTAINER_INSPECTION"
        if len(payload_data) < payload_bytes:
            payload_inspection["limitations"].append("Some appended bytes lie outside the inspected range")
        limitations.extend(payload_inspection["limitations"])
    if signature["integrity"] == "UNKNOWN":
        limitations.append("Authenticode verification inconclusive; see signature checks.")
    disassembly = disassembly_facts(binary)
    return {"schema_version": "2.2", "file": {"file_name": path.name, "file_path": str(path), "file_size": size,
            "sha256": digest.hexdigest(), "format": str(binary.format), "machine": str(binary.header.machine),
            "entry_point": hex(binary.entrypoint), "section_count": len(sections), "sections": sections, "overlay": overlay},
            "imports": {"libraries": libraries, "library_count": len(libraries), "function_count": sum(len(lib["functions"]) for lib in libraries)},
            "strings": strings, "signature": signature, "disassembly": disassembly,
            "payload_inspection": payload_inspection,
            "suspicious_instructions": {"count": 0, "instructions": [], "scored": False, "supported": disassembly["supported"]},
            "coverage": {"static_only": True, "limitations": limitations,
                         "yara": "NOT_CONFIGURED", "hash_reputation": "NOT_CONFIGURED",
                         "unpacking": "BOUNDED_ZIP_AND_LITERAL_SCRIPT_DECODING" if payload_inspection else "NOT_PERFORMED",
                         "control_flow": "NOT_ANALYZED"}}


async def analyze_file(target_file):
    return await asyncio.to_thread(_analyze, Path(target_file))


async def output(target_file):
    return await analyze_file(target_file)
