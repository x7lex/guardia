"""Bounded, static-only extraction of Windows PE facts. Never loads target code."""

import asyncio
import hashlib
import re
from pathlib import Path

import capstone
import lief

from backend.features import STRING_PATTERNS
from backend.signatures import recognized_issuer
from backend.payloads import inspect_payload
from backend.yara_scan import inspect_yara
from backend.pe_metadata import overlay_layout, resource_facts

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
    for regex, encoding in (
        (rb"[\x20-\x7e]{5,2048}", "ascii"),
        (rb"(?:[\x20-\x7e]\x00){5,2048}", "utf-16le"),
    ):
        for raw in re.finditer(regex, data):
            value = raw.group().decode(encoding)
            for category, pattern in patterns.items():
                for match in pattern.finditer(value):
                    counts[category] += 1
                    entry = match.group()[:500]
                    if (
                        entry not in matches[category]
                        and len(matches[category]) < MAX_MATCHES
                    ):
                        matches[category].append(entry)
    return {
        "matches": matches,
        "match_counts": counts,
        "limits": {
            "examples_per_category": MAX_MATCHES,
            "printable_run_characters": 2048,
        },
        "note": "ASCII and ASCII-range UTF-16LE only; text is untrusted data. URLs/domains/IP-like strings carry no risk by themselves.",
    }


def get_signatures(binary):
    result = {
        "signed": bool(binary.has_signatures),
        "integrity": "UNSIGNED",
        "chain_trust": "NOT_EVALUATED",
        "revocation": "NOT_CHECKED",
        "publisher_identity": "NOT_TRUST_VALIDATED",
        "publishers": [],
        "checks": [],
        "known_ca": False,
    }
    if not binary.has_signatures:
        directory = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
        if directory and directory.size:
            result.update(signed=True, integrity="UNKNOWN")
            result["checks"].append(
                {"error": "Certificate table exists but no signature could be parsed"}
            )
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
            bad_mask = int(getattr(flags, "BAD_DIGEST", 0)) | int(
                getattr(flags, "BAD_SIGNATURE", 0)
            )
            invalid |= bool(int(integrity) & bad_mask) or bool(
                int(digest) & int(getattr(flags, "BAD_DIGEST", 0))
            )
            result["checks"].append(
                {
                    "full_verification": str(full),
                    "integrity_without_time": str(integrity),
                    "file_digest": str(digest),
                }
            )
            for signer in signature.signers:
                cert = signer.cert
                if cert is not None:
                    result["publishers"].append(
                        {
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "serial_number": bytes(cert.serial_number).hex(),
                        }
                    )
        except (RuntimeError, ValueError, TypeError, AttributeError) as error:
            result["checks"].append({"error": str(error)})
    # Preserve a failing signature even if another embedded signature passes.
    result["integrity"] = "INVALID" if invalid else "VALID" if valid else "UNKNOWN"
    result["known_ca"] = any(recognized_issuer(p["issuer"]) for p in result["publishers"])
    return result


def disassembly_facts(binary):
    modes = {lief.PE.Header.MACHINE_TYPES.I386: capstone.CS_MODE_32,
             lief.PE.Header.MACHINE_TYPES.AMD64: capstone.CS_MODE_64}
    result = {"supported": binary.header.machine in modes, "scored": True,
              "scope": "At most 4096 raw bytes at the entry point; linear decoding is not a control-flow graph",
              "bytes_decoded": 0, "instruction_count": 0, "mnemonic_counts": {}}
    if not result["supported"]:
        return result
    rva = binary.optional_header.addressof_entrypoint
    for section in binary.sections:
        offset = rva - section.virtual_address
        if 0 <= offset < len(section.content) and section.has_characteristic(
            lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
        ):
            disassembler = capstone.Cs(
                capstone.CS_ARCH_X86, modes[binary.header.machine]
            )
            for _, size, mnemonic, _ in disassembler.disasm_lite(
                bytes(section.content)[offset : offset + 4096], binary.entrypoint
            ):
                result["bytes_decoded"] += size
                result["instruction_count"] += 1
                result["mnemonic_counts"][mnemonic] = (
                    result["mnemonic_counts"].get(mnemonic, 0) + 1
                )
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
                sample.extend(chunk[: MAX_STRING_BYTES - len(sample)])
    binary = lief.PE.parse(str(path))
    if binary is None:
        raise UnsupportedFileError("LIEF could not parse PE headers")
    sections = []
    for section in binary.sections:
        sections.append(
            {
                "name": section.name,
                "virtual_address": hex(section.virtual_address),
                "virtual_size": section.virtual_size,
                "raw_size": section.sizeof_raw_data,
                "raw_offset": section.pointerto_raw_data,
                "entropy": round(section.entropy, 3),
                "executable": section.has_characteristic(
                    lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
                ),
                "writable": section.has_characteristic(
                    lief.PE.Section.CHARACTERISTICS.MEM_WRITE
                ),
                "raw_out_of_bounds": bool(
                    section.sizeof_raw_data
                    and section.pointerto_raw_data + section.sizeof_raw_data > size
                ),
            }
        )
    libraries = []
    limitations = []
    for kind, imports in (("normal", binary.imports), ("delay", binary.delay_imports)):
        for library in imports:
            libraries.append(
                {
                    "name": library.name,
                    "kind": kind,
                    "functions": [
                        f"ordinal:{entry.ordinal}" if entry.is_ordinal else entry.name
                        for entry in library.entries
                    ],
                }
            )
    strings = extract_strings(bytes(sample))
    strings.update(bytes_scanned=len(sample), truncated=size > len(sample))
    if strings["truncated"]:
        limitations.append(
            "String scan limited to first 32 MiB; later strings may be missed."
        )
    if not libraries:
        limitations.append(
            "No named import tables available; packed or dynamically resolved capabilities may be hidden."
        )
    signature = get_signatures(binary)
    section_end = max(
        [binary.optional_header.sizeof_headers]
        + [
            section.pointerto_raw_data + section.sizeof_raw_data
            for section in binary.sections
            if section.sizeof_raw_data
        ]
    )
    certificate = binary.data_directory(lief.PE.DataDirectory.TYPES.CERTIFICATE_TABLE)
    overlay = overlay_layout(
        size,
        section_end,
        certificate.rva if certificate else 0,
        certificate.size if certificate else 0,
    )
    payload_inspection = None
    if overlay["payload_bytes"]:
        inspections = []
        remaining = MAX_STRING_BYTES
        with path.open("rb") as source:
            for region in overlay["payload_ranges"]:
                source.seek(region["offset"])
                data = source.read(min(region["size"], remaining))
                remaining -= len(data)
                item = inspect_payload(
                    data, region["offset"], source=f"overlay@{region['offset']}"
                )
                item["truncated"] = len(data) < region["size"]
                if item["truncated"]:
                    item["status"] = "partial"
                    item["limitations"].append(
                        "Some appended bytes lie outside the inspected range"
                    )
                inspections.append(item)
        if len(inspections) == 1:
            payload_inspection = inspections[0]
        else:
            payload_inspection = {
                "regions": inspections,
                "bytes_inspected": sum(i["bytes_inspected"] for i in inspections),
                "status": "inspected"
                if all(i["status"] == "inspected" for i in inspections)
                else "partial",
                "truncated": any(i["truncated"] for i in inspections),
                "container_candidates": [
                    c for i in inspections for c in i["container_candidates"]
                ],
                "limitations": [
                    reason for i in inspections for reason in i["limitations"]
                ],
            }
        overlay["content_analysis"] = "BOUNDED_STATIC_CONTAINER_INSPECTION"
        limitations.extend(payload_inspection["limitations"])
    if overlay["certificate_range_valid"] is False:
        limitations.append(
            "Certificate table range is invalid; its claimed bytes were not excluded from payload inspection"
        )
    version_info, resources = resource_facts(binary)
    if signature["integrity"] == "UNKNOWN":
        limitations.append(
            "Authenticode verification inconclusive; see signature checks."
        )
    disassembly = disassembly_facts(binary)
    yara = inspect_yara(path)
    entry_rva = binary.optional_header.addressof_entrypoint
    header_anomalies = []
    if entry_rva and not any(s.virtual_address <= entry_rva < s.virtual_address + max(s.virtual_size, s.sizeof_raw_data) for s in binary.sections):
        header_anomalies.append("Entry point is outside all sections")
    if binary.optional_header.sizeof_headers > size:
        header_anomalies.append("Declared headers exceed file size")
    return {"schema_version": "5.0", "file": {"file_name": path.name, "file_path": str(path), "file_size": size,
            "sha256": digest.hexdigest(), "format": str(binary.format), "machine": str(binary.header.machine),
            "entry_point": hex(binary.entrypoint), "section_count": len(sections), "sections": sections, "overlay": overlay,
            "version_info": version_info, "header_anomalies": header_anomalies,
            "coff_timestamp": binary.header.time_date_stamps, "entry_point_rva": entry_rva,
            "image_size": binary.optional_header.sizeof_image, "header_size": binary.optional_header.sizeof_headers, "is_dll": binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)},
            "imports": {"libraries": libraries, "library_count": len(libraries), "function_count": sum(len(lib["functions"]) for lib in libraries)},
            "strings": strings, "signature": signature, "disassembly": disassembly,
            "payload_inspection": payload_inspection, "resources": resources, "yara": yara,
            "suspicious_instructions": {"count": 0, "instructions": [], "scored": False, "supported": disassembly["supported"]},
            "coverage": {"static_only": True, "limitations": limitations,
                         "yara": yara["status"], "hash_reputation": "SEPARATE_REPORT_FIELD",
                         "unpacking": "BOUNDED_ZIP_AND_LITERAL_SCRIPT_DECODING" if payload_inspection else "NOT_PERFORMED",
                         "control_flow": "NOT_ANALYZED"}}


async def analyze_file(target_file):
    return await asyncio.to_thread(_analyze, Path(target_file))


async def output(target_file):
    return await analyze_file(target_file)
