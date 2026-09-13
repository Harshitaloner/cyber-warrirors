"""
pcap_reader.py
Minimal, dependency-free reader for classic libpcap (.pcap) files.
Supports both byte orders. Does NOT depend on scapy/pyshark so the whole
analyser runs with only the Python standard library at its core.
"""
import struct
from dataclasses import dataclass
from typing import List


PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAP_MAGIC_NS_LE = 0xa1b23c4d  # nanosecond-resolution variant


@dataclass
class RawPacket:
    index: int
    timestamp: float
    data: bytes


class PcapParseError(Exception):
    pass


def read_pcap(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    return read_pcap_bytes(raw)


def read_pcap_bytes(raw: bytes) -> List[RawPacket]:
    if len(raw) < 24:
        raise PcapParseError("File too small to be a valid pcap file.")

    magic = struct.unpack("<I", raw[0:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
        ns_res = magic == PCAP_MAGIC_NS_LE
    else:
        magic_be = struct.unpack(">I", raw[0:4])[0]
        if magic_be in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian = ">"
            ns_res = magic_be == PCAP_MAGIC_NS_LE
        else:
            raise PcapParseError(
                "Not a classic .pcap file (bad magic number). "
                "pcapng (.pcapng) is not supported by this MVP parser -- "
                "re-save the capture as classic pcap in Wireshark "
                "(File > Export Specified Packets > .pcap)."
            )

    # global header: magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4)
    # snaplen(4) network(4)
    _, _, _, _, _, _, network = struct.unpack(endian + "IHHiIII", raw[0:24])

    packets: List[RawPacket] = []
    offset = 24
    idx = 0
    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + "IIII", raw[offset:offset + 16]
        )
        offset += 16
        if offset + incl_len > len(raw):
            break
        data = raw[offset:offset + incl_len]
        offset += incl_len
        ts = ts_sec + (ts_usec / 1_000_000_000 if ns_res else ts_usec / 1_000_000)
        packets.append(RawPacket(index=idx, timestamp=ts, data=data))
        idx += 1

    return packets, network


def linktype_name(network: int) -> str:
    return {
        1: "Ethernet",
        101: "Raw IP",
        113: "Linux cooked capture (SLL)",
        276: "Linux cooked capture v2 (SLL2)",
    }.get(network, f"Unknown (DLT {network})")
