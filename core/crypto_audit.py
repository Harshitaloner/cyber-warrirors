"""
crypto_audit.py
Grades the algorithms found in IKE transforms against a simple, editable
compliance rulebase (loosely modeled after NIST SP 800-77 / CNSA guidance).
"""
from dataclasses import dataclass
from typing import List
from .ike_dissector import IsakmpMessage

WEAK_TERMS = {
    "DES-CBC": "Single DES -- 56-bit effective key, trivially brute-forced today.",
    "3DES-CBC": "3DES -- deprecated (NIST SP 800-131A disallows new use).",
    "3DES": "3DES -- deprecated (NIST SP 800-131A disallows new use).",
    "IDEA-CBC": "IDEA -- legacy, largely unaudited in modern contexts.",
    "Blowfish-CBC": "Blowfish -- 64-bit block size, vulnerable to SWEET32.",
    "Blowfish": "Blowfish -- 64-bit block size, vulnerable to SWEET32.",
    "RC5-R16-B64-CBC": "RC5 -- legacy cipher, not recommended.",
    "CAST-CBC": "CAST-128 -- legacy 64-bit block cipher.",
    "CAST": "CAST-128 -- legacy 64-bit block cipher.",
    "DES-IV64": "DES variant -- 56-bit effective key.",
    "DES": "DES -- 56-bit effective key, trivially brute-forced today.",
    "MD5": "MD5 -- collision-broken, unsuitable for integrity/PRF use.",
    "HMAC-MD5-96": "HMAC-MD5 -- weak hash primitive, avoid in new deployments.",
    "PRF-HMAC-MD5": "MD5-based PRF -- weak hash primitive.",
    "DH1 (768-bit MODP)": "DH Group 1 (768-bit) -- breakable with modest resources.",
    "DH2 (1024-bit MODP)": "DH Group 2 (1024-bit) -- below modern minimums (Logjam-class risk).",
    "Pre-Shared Key": None,  # not weak by itself; flagged separately for Aggressive Mode
}

STRONG_HINTS = {
    "AES-CBC", "AES-CTR", "AES-GCM-16", "AES-GCM-8", "AES-CCM-16",
    "CHACHA20-POLY1305", "SHA2-256", "SHA2-384", "SHA2-512",
    "HMAC-SHA2-256-128", "HMAC-SHA2-384-192", "HMAC-SHA2-512-256",
    "DH14 (2048-bit MODP)", "DH15 (3072-bit MODP)", "DH19 (256-bit ECP)",
    "DH20 (384-bit ECP)", "DH21 (521-bit ECP)", "PRF-HMAC-SHA2-256",
}


@dataclass
class Finding:
    severity: str          # "critical" | "warning" | "info"
    source_packet: int
    title: str
    detail: str


def audit_messages(messages: List[IsakmpMessage]) -> List[Finding]:
    findings: List[Finding] = []

    for m in messages:
        # Aggressive Mode itself is a known exposure (PSK hash sent before encryption).
        if not m.version_major == 2 and m.exchange_name == "Aggressive Mode":
            findings.append(Finding(
                severity="warning",
                source_packet=m.packet_index,
                title="IKEv1 Aggressive Mode in use",
                detail=("Aggressive Mode exchanges the PSK authentication hash "
                        "in the clear during negotiation, making offline dictionary "
                        "attacks against weak pre-shared keys possible (well-known "
                        "exposure, e.g. as leveraged by tools like ike-scan)."),
            ))

        seen_algo_strings = set()
        for t in m.transforms:
            for chunk in t.algorithm.split(", "):
                if "=" in chunk:
                    _, _, value = chunk.partition("=")
                else:
                    value = chunk
                value = value.strip()
                if not value or value in seen_algo_strings:
                    continue
                seen_algo_strings.add(value)
                if value in WEAK_TERMS and WEAK_TERMS[value]:
                    findings.append(Finding(
                        severity="critical",
                        source_packet=m.packet_index,
                        title=f"Weak algorithm proposed: {value}",
                        detail=WEAK_TERMS[value] + f" (seen in {t.proto_or_type})",
                    ))

        for n in m.notifies:
            sev = "critical" if n.message_name in (
                "NO_PROPOSAL_CHOSEN", "AUTHENTICATION_FAILED", "INVALID_SYNTAX",
                "INVALID_COOKIE", "INVALID_KEY_INFORMATION",
            ) else "warning"
            findings.append(Finding(
                severity=sev,
                source_packet=m.packet_index,
                title=f"IKE Notify: {n.message_name}",
                detail=f"Notify message type {n.message_type} received in "
                       f"{m.exchange_name} exchange.",
            ))

    return findings


def score_posture(findings: List[Finding]) -> dict:
    critical = sum(1 for f in findings if f.severity == "critical")
    warning = sum(1 for f in findings if f.severity == "warning")
    score = max(0, 100 - critical * 25 - warning * 10)
    if score >= 85:
        grade = "A - Compliant"
    elif score >= 60:
        grade = "B - Needs Attention"
    elif score >= 35:
        grade = "C - At Risk"
    else:
        grade = "D - Non-Compliant"
    return {"score": score, "grade": grade, "critical": critical, "warning": warning}
