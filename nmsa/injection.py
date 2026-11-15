"""Static prompt-injection indicators; does not run an LLM or execute instructions."""
from __future__ import annotations
import re

HEURISTICS = {
    "authority_spoof": re.compile(r"(?:system\s+(?:message|prompt)|developer\s+(?:message|instruction)|\[im_start\]system|<\|im_start\|>system)", re.I),
    "instruction_override": re.compile(r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+(?:instructions|rules|messages|prompts)", re.I),
    "credential_exfiltration": re.compile(r"(?:send|upload|post|exfiltrate|transmit)\s+.{0,90}(?:secret|token|api.key|password|\.env)", re.I),
    "safety_disable": re.compile(r"(?:disable|bypass|turn.off)\s+(?:all\s+)?(?:safety|security|audit|logging|guardrails)", re.I),
    "tool_instruction": re.compile(r"(?:run|execute|invoke)\s+.{0,65}(?:powershell|terminal|shell|bash|curl|wget)", re.I),
}


def inspect_text(text):
    """Return category and line only: never copy potentially secret text."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for name, regex in HEURISTICS.items():
            if regex.search(line):
                findings.append({"category": name, "line": line_no, "review": "UNVERIFIED"})
    return findings
