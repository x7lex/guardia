"""Bounded, in-memory inspection of embedded archives. No payload files written."""

import io
import math
import struct
import time
import zipfile
from collections import Counter
from pathlib import PurePosixPath

from backend.scripts import inspect_python

SIGNATURES = {
    "zip": b"PK\x03\x04", "gzip": b"\x1f\x8b\x08", "xz": b"\xfd7zXZ\x00",
    "bzip2": b"BZh", "zstandard": b"\x28\xb5\x2f\xfd", "7zip": b"7z\xbc\xaf\x27\x1c",
    "cabinet": b"MSCF", "pyinstaller": b"MEI\x0c\x0b\x0a\x0b\x0e",
}
MAX_MEMBERS = 512
MAX_SCRIPT = 2 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def _inspect_zip(data, source, budget, depth=0):
    result = {"source": source, "format": "zip", "members": [], "scripts": [],
              "nested_archives": [], "limitations": [], "status": "partial"}
    # Check the central directory limits before ZipFile allocates an entry for
    # every member. ZIP64 and multi-disk archives are intentionally unsupported.
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        result["limitations"].append("ZIP end record not found in bounded input")
        return result
    _, disk, directory_disk, count_disk, count, directory_size, _, comment = struct.unpack_from("<4s4H2IH", data, end)
    if disk or directory_disk or count_disk != count or count > MAX_MEMBERS or directory_size > 2 * 1024 * 1024 or end + 22 + comment > len(data):
        result["limitations"].append("ZIP exceeds directory limits, uses ZIP64/multiple disks, or is truncated")
        return result
    archive_end = end + 22 + comment
    result["trailing_bytes"] = len(data) - archive_end
    if result["trailing_bytes"]:
        result["limitations"].append("Bytes after the ZIP end record remain uninspected")
    data = data[:archive_end]
    result["member_count"] = count
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            result["prefix_bytes"] = min((member.header_offset for member in members), default=archive.start_dir)
            if result["prefix_bytes"]:
                result["limitations"].append("Bytes before the first ZIP member remain uninspected")
            if len(members) > MAX_MEMBERS:
                result["limitations"].append("ZIP member limit exceeded")
                return result
            # Prioritize source before nested standard-library archives use the budget.
            members.sort(key=lambda m: (PurePosixPath(m.filename).suffix.lower() not in {".py", ".pyw"}, m.filename))
            for member in members:
                suffix = PurePosixPath(member.filename).suffix.lower()
                record = {"name": member.filename[:300], "size": member.file_size,
                          "compressed_size": member.compress_size, "kind": "native" if suffix in {".exe", ".dll", ".pyd", ".sys"} else "bytecode" if suffix in {".pyc", ".pyo"} else "source" if suffix in {".py", ".pyw"} else "archive" if suffix in {".zip", ".pyz", ".whl"} else "other", "status": "not_analyzed"}
                result["members"].append(record)
                if member.is_dir():
                    record["status"] = "directory"
                    continue
                if time.monotonic() > budget["deadline"]:
                    record["status"] = "time_limit"
                    continue
                limit = MAX_SCRIPT if suffix in {".py", ".pyw"} else MAX_ARCHIVE
                if member.flag_bits & 1:
                    record["status"] = "encrypted"
                    continue
                if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    record["status"] = "unsupported_compression"
                    continue
                if member.file_size > limit or member.file_size > budget["remaining"] or member.file_size / max(member.compress_size, 1) > 200:
                    record["status"] = "decompression_limit"
                    continue
                if record["kind"] in {"native", "bytecode", "other"}:
                    # Inventory opaque members without interpreting bytecode or loading native code.
                    record["status"] = record["kind"] + "_uninspected"
                    continue
                try:
                    with archive.open(member) as stream:
                        content = stream.read(min(limit, budget["remaining"]) + 1)
                    if len(content) > limit or len(content) > budget["remaining"]:
                        record["status"] = "decompression_limit"
                        continue
                    budget["remaining"] -= len(content)
                    member_source = source + "::" + member.filename[:300]
                    if suffix in {".py", ".pyw"}:
                        script = inspect_python(content, member_source, budget=budget["script_budget"])
                        result["scripts"].append(script)
                        record["status"] = script["status"]
                    elif depth < 2:
                        result["nested_archives"].append(_inspect_zip(content, member_source, budget, depth + 1))
                        record["status"] = "nested_archive"
                    else:
                        record["status"] = "nesting_limit"
                except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as error:
                    record.update(status="error", error=type(error).__name__)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        result["limitations"].append(f"ZIP parsing failed: {type(error).__name__}")
    counts = Counter(m["status"] for m in result["members"])
    result["member_status_counts"] = dict(counts)
    if any(counts.get(key) for key in ("not_analyzed", "native_uninspected", "bytecode_uninspected", "other_uninspected")):
        result["limitations"].append("Native binaries, bytecode and non-source members have not been semantically analyzed")
    if any(status not in {"inspected", "directory", "nested_archive", "not_analyzed"} for status in counts):
        result["limitations"].append("Some members exceeded limits, were encrypted, unsupported or failed inspection")
    result["coverage_summary"] = {
        "member_bytes": sum(m["size"] for m in result["members"]),
        "inspected_source_bytes": sum(m["size"] for m in result["members"] if m["status"] == "inspected"),
        "native_member_bytes": sum(m["size"] for m in result["members"] if m.get("kind") == "native"),
        "bytecode_member_bytes": sum(m["size"] for m in result["members"] if m.get("kind") == "bytecode"),
        "note": "Byte accounting is not semantic coverage; metadata and source inspection do not imply full behavior recovery.",
    }
    if (not result["limitations"] and all(m["status"] in {"inspected", "directory", "nested_archive"} for m in result["members"])
            and all(child["status"] == "inspected" for child in result["nested_archives"])):
        result["status"] = "inspected"
    return result


def inspect_payload(data, file_offset=0, source="overlay"):
    sample = data[:1024 * 1024]
    counts = Counter(sample)
    entropy = -sum((count / len(sample)) * math.log2(count / len(sample)) for count in counts.values()) if sample else 0
    candidates = []
    for kind, magic in SIGNATURES.items():
        start = 0
        for _ in range(8):
            offset = data.find(magic, start)
            if offset < 0:
                break
            candidates.append({"format": kind, "offset": file_offset + offset, "relative_offset": offset})
            start = offset + len(magic)
    result = {"source": source, "bytes_inspected": len(data), "entropy_sample_bytes": len(sample), "entropy": round(entropy, 3),
              "container_candidates": sorted(candidates, key=lambda c: c["offset"]),
              "status": "not_decoded", "limitations": [],
              "limits": {"members_per_archive": MAX_MEMBERS, "source_bytes": MAX_SCRIPT,
                         "total_decompressed_bytes": MAX_TOTAL, "nested_archive_depth": 2}}
    if any(c["format"] == "zip" for c in candidates):
        budget = {"remaining": MAX_TOTAL, "deadline": time.monotonic() + 10, "script_budget": {"bytes": 8 * 1024 * 1024, "layers": 32}}
        result["archive"] = _inspect_zip(data, source, budget)
        result["status"] = result["archive"]["status"]
        result["decompressed_bytes"] = MAX_TOTAL - budget["remaining"]
        if result["status"] != "inspected":
            result["limitations"].append("Archive source inspected statically; native members, bytecode and unsupported dynamic layers remain opaque")
    elif data:
        result["limitations"].append("No supported ZIP container; payload content remains opaque")
    return result


def script_findings(inspection):
    """Yield source-local findings without combining unrelated archive members."""
    if not inspection:
        return

    def script_walk(script):
        yield from script.get("findings", [])
        for child in script.get("decoded_layers", []):
            yield from script_walk(child)

    def archive_walk(archive):
        for script in archive.get("scripts", []):
            yield from script_walk(script)
        for nested in archive.get("nested_archives", []):
            yield from archive_walk(nested)

    yield from archive_walk(inspection.get("archive", {}))
    for region in inspection.get("regions", []):
        yield from script_findings(region)
