"""Remove common Markdown presentation syntax from short model reviews."""

import re


def plain_text_review(text):
    # Keep link destinations and quoted/code evidence; remove only presentation.
    text = re.sub(r"!?\[([^\]\n]+)\]\(([^\s)]+)\)", r"\1 (\2)", text)
    text = re.sub(r"<((?:https?://|mailto:)[^>\n]+)>", r"\1", text)
    lines = []
    fenced = False
    for line in text.splitlines():
        if re.match(r"^\s*(?:`{3,}|~{3,})", line):
            fenced = not fenced
            lines.append("")
            continue
        if not fenced:
            if re.fullmatch(
                r"\s*(?:(?:[-*_]\s*){3,}|={3,}|\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?)\s*",
                line,
            ):
                continue
            line = re.sub(r"^\s*(?:>\s*)+", "", line)
            line = re.sub(r"^\s*#{1,6}\s+(.+?)(?:\s+#+)?\s*$", r"\1", line)
            line = re.sub(r"^\s*(?:[-+*•]|\d+[.)])\s+(?:\[[ xX]\]\s+)?", "", line)
            if line.strip().startswith("|") and line.strip().endswith("|"):
                line = "; ".join(
                    part.strip() for part in line.strip().strip("|").split("|")
                )
            code_spans = []

            def protect_code(match) -> str:
                code_spans.append(match.group(2))  # noqa: B023
                return f"\x00CODE{len(code_spans) - 1}\x00"  # noqa: B023

            line = re.sub(r"(`+)([^`]+)\1", protect_code, line)
            # Word boundaries preserve identifiers such as risk_assessment and
            # paths such as C:\\temp\\_internal_\\sample.exe.
            for marker in ("**", "__", "~~", "*", "_"):
                escaped = re.escape(marker)
                line = re.sub(
                    r"(?<![\w\\/])"
                    + escaped
                    + r"(?=\S)(.+?)(?<=\S)"
                    + escaped
                    + r"(?!\w)",
                    r"\1",
                    line,
                )
            for index, code in enumerate(code_spans):
                line = line.replace(f"\x00CODE{index}\x00", code)
        lines.append(line.rstrip())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
