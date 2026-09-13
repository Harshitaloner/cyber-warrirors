"""
diagnostics.py
Turns raw session/notify data into plain-English root-cause explanations,
the way a senior network engineer would describe them.
"""
from typing import List
from .state_engine import TunnelSession

NOTIFY_EXPLANATIONS = {
    "NO_PROPOSAL_CHOSEN": (
        "The responder rejected every offered cryptographic proposal. This is the "
        "single most common cause of IPsec tunnel failures -- almost always a "
        "mismatch in encryption algorithm, hash/PRF, DH group, or SA lifetime "
        "between the two endpoint configurations."
    ),
    "AUTHENTICATION_FAILED": (
        "Peer authentication failed -- check for a pre-shared key mismatch, an "
        "expired/incorrect certificate, or an identity (ID payload) type mismatch "
        "between the two ends."
    ),
    "INVALID_COOKIE": (
        "The peer does not recognise the initiator/responder SPI (cookie) pair, "
        "typically because the remote SA was cleared/rebooted and stale state is "
        "still cached locally."
    ),
    "INVALID_SYNTAX": (
        "Malformed ISAKMP payload -- often caused by interoperability bugs between "
        "vendor implementations or a corrupted/incomplete capture."
    ),
    "INVALID_KEY_INFORMATION": (
        "Key exchange (KE) payload was rejected, usually because the DH group used "
        "by the initiator does not match what the responder's policy expects."
    ),
    "TS_UNACCEPTABLE": (
        "IKEv2 Traffic Selectors did not match -- the two sides disagree on which "
        "subnets/ports the child SA should protect."
    ),
    "INVALID_ID_INFORMATION": (
        "The peer's identity (IDi/IDr) did not match what was configured/expected "
        "on the responder."
    ),
}


def explain_session(session: TunnelSession) -> List[str]:
    notes: List[str] = []
    all_notifies = [(m.packet_index, n) for m in session.messages for n in m.notifies]

    if session.established:
        notes.append(
            f"Tunnel {session.session_key} between {session.peer_a} and "
            f"{session.peer_b} completed negotiation successfully "
            f"({session.ike_version})."
        )
        return notes

    if not all_notifies:
        exch_seen = [m.exchange_name for m in session.messages]
        if session.ike_version == "IKEv2" and "IKE_SA_INIT" in exch_seen and "IKE_AUTH" not in exch_seen:
            notes.append(
                f"IKE_SA_INIT completed but IKE_AUTH was never observed for "
                f"{session.peer_a} <-> {session.peer_b}. The tunnel stalled after "
                f"the initial Diffie-Hellman exchange -- likely causes: EAP/certificate "
                f"authentication timeout, a firewall dropping subsequent UDP 500/4500 "
                f"packets, or the capture ending mid-negotiation."
            )
        elif session.ike_version == "IKEv1" and not any(
            e in ("Identity Protection (Main Mode)", "Aggressive Mode") for e in exch_seen
        ):
            notes.append("Only partial IKEv1 exchange captured -- Phase 1 never completed.")
        elif "Quick Mode" not in exch_seen and session.ike_version == "IKEv1":
            notes.append(
                f"Phase 1 (Main/Aggressive Mode) completed between {session.peer_a} and "
                f"{session.peer_b}, but no Phase 2 Quick Mode negotiation was observed -- "
                f"the IKE SA was established but no child SA / traffic tunnel followed."
            )
        else:
            notes.append(
                f"Tunnel {session.session_key} did not reach a confirmed established "
                f"state within the capture window."
            )
    else:
        for pkt_idx, n in all_notifies:
            explanation = NOTIFY_EXPLANATIONS.get(
                n.message_name,
                f"Notify type {n.message_type} ({n.message_name}) received -- "
                f"consult RFC 7296 / RFC 2408 for exact semantics.",
            )
            notes.append(f"[packet #{pkt_idx}] {n.message_name}: {explanation}")

    return notes
