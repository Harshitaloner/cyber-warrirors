"""
packet_dissector.py
Pure-stdlib dissection of Ethernet/Linux-cooked -> IPv4 -> UDP/ESP/AH.
Only unpacks what the IPsec analyser needs (no full protocol stack).
"""
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DissectedPacket:
    index: int
    timestamp: float
    src_ip: str = ""
    dst_ip: str = ""
    ip_proto: int = 0
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload: bytes = b""
    kind: str = "other"   # "isakmp" | "esp" | "ah" | "other"
    length: int = 0


def _ip_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _extract_ipv4(data: bytes):
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    version = ver_ihl >> 4
    if version != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack(">H", data[2:4])[0]
    proto = data[9]
    src = _ip_to_str(data[12:16])
    dst = _ip_to_str(data[16:20])
    body = data[ihl:total_len] if total_len and total_len <= len(data) else data[ihl:]
    return src, dst, proto, body


def dissect(raw_data: bytes, linktype: int):
    """Strip link-layer framing and return the IPv4 payload + proto info."""
    data = raw_data
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        offset = 14
        # Skip 802.1Q VLAN tag if present
        if ethertype == 0x8100:
            if len(data) < 18:
                return None
            ethertype = struct.unpack(">H", data[16:18])[0]
            offset = 18
        if ethertype != 0x0800:  # not IPv4
            return None
        data = data[offset:]
    elif linktype == 101:  # Raw IP
        pass
    elif linktype in (113, 276):  # Linux cooked capture
        header_len = 16 if linktype == 113 else 20
        if len(data) < header_len:
            return None
        data = data[header_len:]
    else:
        return None

    result = _extract_ipv4(data)
    return result


def parse_packet(index: int, timestamp: float, raw_data: bytes, linktype: int) -> Optional[DissectedPacket]:
    ip_info = dissect(raw_data, linktype)
    if ip_info is None:
        return None
    src, dst, proto, body = ip_info

    pkt = DissectedPacket(
        index=index, timestamp=timestamp, src_ip=src, dst_ip=dst,
        ip_proto=proto, length=len(raw_data),
    )

    if proto == 17:  # UDP
        if len(body) < 8:
            return None
        sport, dport, udp_len, _csum = struct.unpack(">HHHH", body[0:8])
        udp_payload = body[8:udp_len] if udp_len and udp_len <= len(body) else body[8:]
        pkt.src_port = sport
        pkt.dst_port = dport
        if sport in (500, 4500) or dport in (500, 4500):
            # For NAT-T (port 4500), the first 4 bytes are a non-ESP marker
            # (0x00000000) before the ISAKMP header, unless it's an ESP-in-UDP
            # packet (marker would be nonzero -> that's the ESP SPI itself).
            if dport == 4500 or sport == 4500:
                if len(udp_payload) >= 4 and udp_payload[0:4] == b"\x00\x00\x00\x00":
                    udp_payload = udp_payload[4:]
                    pkt.kind = "isakmp"
                elif len(udp_payload) >= 8:
                    pkt.kind = "esp"
                else:
                    pkt.kind = "other"
            else:
                pkt.kind = "isakmp"
            pkt.payload = udp_payload
        else:
            pkt.payload = udp_payload
    elif proto == 50:  # ESP
        pkt.kind = "esp"
        pkt.payload = body
    elif proto == 51:  # AH
        pkt.kind = "ah"
        pkt.payload = body
    else:
        pkt.payload = body

    return pkt
