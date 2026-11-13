"""CWE catalog: the Common Weakness Enumeration entries that our rules map to.

Titles and mapping guidance were checked against https://cwe.mitre.org (CWE 5.0, Nov 2026).

`usage` is MITRE's "Vulnerability Mapping" guidance for each entry:
  ALLOWED / ALLOWED-WITH-REVIEW  -> fine to label a security weakness with it.
  PROHIBITED                     -> a code-quality weakness. MITRE says not to use it to label
                                    vulnerabilities (e.g. CVEs). It still describes the quality
                                    problem exactly, so we keep it but mark it as a quality CWE.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Cwe:
    id: str
    name: str    # official MITRE title
    short: str   # our short label for the UI
    usage: str   # MITRE vulnerability-mapping usage

    @property
    def number(self) -> str:
        return self.id.split("-", 1)[1]

    @property
    def url(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.number}.html"

    @property
    def is_quality_only(self) -> bool:
        return self.usage == "PROHIBITED"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "short": self.short,
            "usage": self.usage,
            "url": self.url,
            "quality_only": self.is_quality_only,
        }


_CWES = [
    # security weaknesses
    Cwe("CWE-95", "Improper Neutralization of Directives in Dynamically Evaluated Code",
        "Eval Injection", "ALLOWED"),
    Cwe("CWE-78", "Improper Neutralization of Special Elements used in an OS Command",
        "OS Command Injection", "ALLOWED"),
    Cwe("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command",
        "SQL Injection", "ALLOWED"),
    Cwe("CWE-798", "Use of Hard-coded Credentials", "Hard-coded Credentials", "ALLOWED-WITH-REVIEW"),
    Cwe("CWE-259", "Use of Hard-coded Password", "Hard-coded Password", "ALLOWED"),
    Cwe("CWE-502", "Deserialization of Untrusted Data", "Unsafe Deserialization", "ALLOWED"),
    Cwe("CWE-295", "Improper Certificate Validation", "Improper Certificate Validation", "ALLOWED"),
    Cwe("CWE-328", "Use of Weak Hash", "Weak Hash", "ALLOWED"),
    Cwe("CWE-916", "Use of Password Hash With Insufficient Computational Effort",
        "Weak Password Hashing", "ALLOWED"),
    Cwe("CWE-489", "Active Debug Code", "Active Debug Code", "ALLOWED"),
    # error handling and resources
    Cwe("CWE-396", "Declaration of Catch for Generic Exception", "Catch-all Exception Handler", "ALLOWED"),
    Cwe("CWE-1069", "Empty Exception Block", "Empty Exception Block", "ALLOWED"),
    Cwe("CWE-390", "Detection of Error Condition Without Action", "Error Ignored", "ALLOWED"),
    Cwe("CWE-775", "Missing Release of File Descriptor or Handle after Effective Lifetime",
        "File Handle Not Released", "ALLOWED"),
    # code quality
    Cwe("CWE-1108", "Excessive Reliance on Global Variables", "Reliance on Globals", "ALLOWED"),
    Cwe("CWE-546", "Suspicious Comment", "Suspicious Comment", "ALLOWED"),
    Cwe("CWE-1121", "Excessive McCabe Cyclomatic Complexity", "Excessive Complexity", "PROHIBITED"),
    Cwe("CWE-1064", "Invokable Control Element with Signature Containing an Excessive Number of Parameters",
        "Too Many Parameters", "PROHIBITED"),
    Cwe("CWE-1124", "Excessively Deep Nesting", "Excessively Deep Nesting", "PROHIBITED"),
    Cwe("CWE-1111", "Incomplete I/O Documentation", "Incomplete I/O Documentation", "PROHIBITED"),
    Cwe("CWE-1099", "Inconsistent Naming Conventions for Identifiers", "Inconsistent Naming", "PROHIBITED"),
    Cwe("CWE-1078", "Inappropriate Source Code Style or Formatting", "Inappropriate Code Style", "PROHIBITED"),
]

CWES: dict[str, Cwe] = {cwe.id: cwe for cwe in _CWES}
