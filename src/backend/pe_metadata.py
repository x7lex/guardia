"""Bounded PE resource inventory and certificate-aware overlay intervals."""

import math
from collections import Counter

from backend.payloads import SIGNATURES, inspect_payload


def overlay_layout(size, section_end, certificate_offset=0, certificate_size=0):
    start = min(max(0, section_end), size)
    intervals = [(start, size)] if start < size else []
    certificate_bytes = 0
    valid_range = (
        certificate_size > 0
        and certificate_offset >= section_end
        and certificate_offset + certificate_size <= size
    )
    if valid_range:
        certificate_end = certificate_offset + certificate_size
        certificate_bytes = certificate_size
        intervals = [
            (a, b)
            for a, b in ((start, certificate_offset), (certificate_end, size))
            if b > a
        ]
    payload = sum(b - a for a, b in intervals)
    return {
        "offset": section_end,
        "size": max(0, size - section_end),
        "certificate_bytes": certificate_bytes,
        "certificate_range_valid": valid_range if certificate_size else None,
        "payload_bytes": payload,
        "payload_fraction": payload / size if size else 0,
        "payload_ranges": [{"offset": a, "size": b - a} for a, b in intervals],
        "content_analysis": "NOT_PRESENT" if not payload else "NOT_INSPECTED",
    }


def resource_facts(binary):
    result = {
        "entries": [],
        "inspections": [],
        "total_bytes": 0,
        "opaque_bytes": 0,
        "truncated": False,
        "limitations": [],
        "limits": {"nodes": 4096, "leaves": 512, "inspection_bytes": 16 * 1024 * 1024},
    }
    versions = {}
    if not binary.has_resources:
        return versions, result
    try:
        manager = binary.resources_manager
        if manager.has_version:
            version_items = manager.version
            if not isinstance(version_items, (list, tuple)):
                version_items = [version_items]
            for version in version_items[:8]:
                if version.string_file_info:
                    for table in list(version.string_file_info.children)[:8]:
                        for entry in list(table.entries)[:64]:
                            versions[str(entry.key)[:80]] = str(entry.value)[:1000]
        remaining = 16 * 1024 * 1024
        nodes = 0
        stack = [(binary.resources, [])]
        while stack:
            node, path = stack.pop()
            nodes += 1
            if nodes > 4096 or len(result["entries"]) >= 512 or len(path) > 16:
                result["truncated"] = True
                break
            if not node.is_data:
                for child in node.childs:
                    if len(stack) >= 4096:
                        result["truncated"] = True
                        break
                    stack.append(
                        (
                            child,
                            path
                            + [str(child.name) if child.has_name else str(child.id)],
                        )
                    )
                continue
            view = node.content
            size = len(view)
            result["total_bytes"] += size
            prefix = bytes(view[: min(size, 1024 * 1024)])
            counts = Counter(prefix)
            entropy = (
                -sum(
                    (c / len(prefix)) * math.log2(c / len(prefix))
                    for c in counts.values()
                )
                if prefix
                else 0
            )
            formats = [
                kind for kind, magic in SIGNATURES.items() if prefix.startswith(magic)
            ]
            native = prefix.startswith(b"MZ")
            # Icons, bitmaps, strings, menus and version metadata are inventoried
            # without treating their compressed multimedia entropy as executable code.
            standard_data = path and path[0] in {
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "9",
                "12",
                "14",
                "16",
                "24",
            }
            opaque = bool(native or formats or (not standard_data and size >= 65536))
            entry = {
                "path": "/".join(path)[:300],
                "size": size,
                "entropy": round(entropy, 3),
                "kind": "native"
                if native
                else formats[0]
                if formats
                else "resource_data",
                "status": "inventoried",
            }
            if formats and size <= remaining and size <= 16 * 1024 * 1024:
                item = inspect_payload(bytes(view), source="resource::" + entry["path"])
                result["inspections"].append(item)
                remaining -= size
                entry["status"] = item["status"]
                opaque = item["status"] != "inspected"
            elif opaque:
                entry["status"] = "uninspected"
            if opaque:
                result["opaque_bytes"] += size
            result["entries"].append(entry)
        if result["opaque_bytes"]:
            result["limitations"].append(
                "Some executable/container resource contents remain opaque; no native or 7z unpacking is performed"
            )
    except (
        AttributeError,
        TypeError,
        ValueError,
        RuntimeError,
        OverflowError,
    ) as error:
        result["truncated"] = True
        result["limitations"].append(
            f"Resource inventory incomplete: {type(error).__name__}"
        )
    return versions, result
