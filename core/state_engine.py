"""
state_engine.py
Correlates ISAKMP messages into tunnel "sessions" via SPI pairing, and
analyses ESP sequence numbers per (SPI) for anti-replay / packet-loss /
out-of-order detection.
"""
import struct
from dataclasses import dataclass, field
from typing import Dict, List
from .ike_dissector import IsakmpMessage
from .packet_dissector import DissectedPacket


@dataclass
class TunnelSession:
    session_key: str
    initiator_spi: str
    responder_spi: str
    peer_a: str
    peer_b: str
    ike_version: str
    messages: List[IsakmpMessage] = field(default_factory=list)

    @property
    def start_time(self):
        return min(m.timestamp for m in self.messages) if self.messages else 0

    @property
    def end_time(self):
        return max(m.timestamp for m in self.messages) if self.messages else 0

    @property
    def established(self) -> bool:
        names = [m.exchange_name for m in self.messages]
        if self.ike_version == "IKEv2":
            return "IKE_AUTH" in names and not self._has_terminal_failure()
        else:
            # Main/Aggressive completed (Phase 1) AND a Quick Mode seen (Phase 2)
            phase1_done = any(n in ("Identity Protection (Main Mode)", "Aggressive Mode")
                               for n in names) and len(self.messages) >= 4
            phase2_seen = "Quick Mode" in names
            return phase1_done and phase2_seen and not self._has_terminal_failure()

    def _has_terminal_failure(self) -> bool:
        for m in self.messages:
            for n in m.notifies:
                if n.message_name in ("NO_PROPOSAL_CHOSEN", "AUTHENTICATION_FAILED",
                                       "INVALID_SYNTAX", "INVALID_COOKIE",
                                       "INVALID_KEY_INFORMATION"):
                    return True
        return False


ZERO_SPI = "0" * 16


def build_sessions(messages: List[IsakmpMessage]) -> List[TunnelSession]:
    """Group messages by (initiator_spi, responder_spi). The very first packet
    of a negotiation is sent before the responder has assigned its SPI (SPI=0),
    so we fold that placeholder entry into whichever real session later shares
    the same initiator SPI."""
    sessions: Dict[str, TunnelSession] = {}
    init_spi_to_key: Dict[str, str] = {}

    for m in messages:
        key = f"{m.initiator_spi}:{m.responder_spi}"

        if m.responder_spi == ZERO_SPI and m.initiator_spi in init_spi_to_key:
            key = init_spi_to_key[m.initiator_spi]
        elif m.responder_spi != ZERO_SPI:
            placeholder_key = f"{m.initiator_spi}:{ZERO_SPI}"
            if placeholder_key in sessions and m.initiator_spi not in init_spi_to_key:
                # promote the placeholder session to the now-known real key
                sessions[key] = sessions.pop(placeholder_key)
                sessions[key].session_key = key
                sessions[key].responder_spi = m.responder_spi
            init_spi_to_key[m.initiator_spi] = key

        if key not in sessions:
            sessions[key] = TunnelSession(
                session_key=key,
                initiator_spi=m.initiator_spi,
                responder_spi=m.responder_spi,
                peer_a=m.src_ip, peer_b=m.dst_ip,
                ike_version="IKEv2" if m.version_major == 2 else "IKEv1",
            )
        sessions[key].messages.append(m)

    for s in sessions.values():
        s.messages.sort(key=lambda m: m.timestamp)
    return sorted(sessions.values(), key=lambda s: s.start_time)


@dataclass
class EspFlow:
    spi: str
    packets_seen: int = 0
    sequence_numbers: List[int] = field(default_factory=list)
    out_of_order: int = 0
    gaps_detected: int = 0
    max_gap: int = 0
    replay_suspects: int = 0


def analyse_esp(packets: List[DissectedPacket]) -> Dict[str, EspFlow]:
    flows: Dict[str, EspFlow] = {}
    for p in packets:
        if p.kind != "esp" or len(p.payload) < 8:
            continue
        spi_bytes = p.payload[0:4]
        seq = struct.unpack(">I", p.payload[4:8])[0]
        spi = spi_bytes.hex()
        flow = flows.setdefault(spi, EspFlow(spi=spi))
        flow.packets_seen += 1

        if flow.sequence_numbers:
            last = flow.sequence_numbers[-1]
            if seq == last:
                flow.replay_suspects += 1
            elif seq < last:
                flow.out_of_order += 1
            elif seq > last + 1:
                gap = seq - last - 1
                flow.gaps_detected += 1
                flow.max_gap = max(flow.max_gap, gap)
        flow.sequence_numbers.append(seq)
    return flows
