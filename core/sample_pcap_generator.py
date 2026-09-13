"""
sample_pcap_generator.py
Crafts a synthetic-but-structurally-valid classic .pcap file containing:
  1) An IKEv1 Main Mode Phase 1 exchange offering a WEAK proposal
     (3DES / MD5 / DH Group 2) -- should be flagged by crypto_audit.
  2) An IKEv1 Quick Mode Phase 2 that completes the tunnel.
  3) A second, failed negotiation where the responder sends
     NO_PROPOSAL_CHOSEN.
  4) An IKEv2 IKE_SA_INIT / IKE_AUTH exchange with a STRONG proposal
     (AES-GCM / SHA2-256 / DH14) that completes successfully.
  5) A run of ESP packets on one SPI, including one out-of-order and
     one gapped sequence number, to exercise anti-replay analysis.

No scapy/pyshark dependency -- built with struct only, so it is fully
reproducible offline for a hackathon demo.
"""
import struct
import os
import random

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # DLT=1 Ethernet


def _eth_ip_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload: bytes) -> bytes:
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len, random.randint(0, 65535), 0,
        64, 17, 0, _ip(src_ip), _ip(dst_ip),
    )
    ip_header = _fix_ip_checksum(ip_header)
    return eth + ip_header + udp


def _eth_ip_esp(src_mac, dst_mac, src_ip, dst_ip, spi: int, seq: int, body_len=32) -> bytes:
    payload = struct.pack(">II", spi, seq) + os.urandom(body_len)
    eth = dst_mac + src_mac + struct.pack(">H", 0x0800)
    total_len = 20 + len(payload)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len, random.randint(0, 65535), 0,
        64, 50, 0, _ip(src_ip), _ip(dst_ip),
    )
    ip_header = _fix_ip_checksum(ip_header)
    return eth + ip_header + payload


def _ip(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _fix_ip_checksum(header: bytes) -> bytes:
    h = bytearray(header)
    h[10] = 0
    h[11] = 0
    csum = _checksum(bytes(h))
    h[10] = (csum >> 8) & 0xFF
    h[11] = csum & 0xFF
    return bytes(h)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _isakmp_header(init_spi: bytes, resp_spi: bytes, next_payload, version,
                    exch_type, flags, msg_id, total_len) -> bytes:
    return init_spi + resp_spi + struct.pack(">BBBBIl", next_payload, version, exch_type, flags, msg_id, 0)[:12] + \
           struct.pack(">I", total_len)


def _gen_payload_header(next_payload, length) -> bytes:
    return struct.pack(">BBH", next_payload, 0, length)


def _ikev1_transform(t_num, t_id, enc=None, hsh=None, auth=None, grp=None, life_secs=28800):
    attrs = b""
    def tv(atype, val):
        return struct.pack(">HH", 0x8000 | atype, val)
    if enc is not None:
        attrs += tv(1, enc)
    if hsh is not None:
        attrs += tv(2, hsh)
    if auth is not None:
        attrs += tv(3, auth)
    if grp is not None:
        attrs += tv(4, grp)
    attrs += tv(11, 1)          # life type = seconds
    attrs += tv(12, life_secs)  # life duration
    body = struct.pack(">BBHB", t_num, t_id, 0, 0)[:4] + attrs
    total_len = 4 + len(attrs)
    header = _gen_payload_header(0, total_len)
    return header + struct.pack(">BBH", t_num, t_id, 0) + attrs


def _ikev1_proposal(prop_num, proto_id, transforms: bytes, num_transforms) -> bytes:
    body = struct.pack(">BBBB", prop_num, proto_id, 0, num_transforms) + transforms
    total_len = 4 + len(body)
    return _gen_payload_header(2, total_len) + body  # next=Proposal placeholder fixed by caller


def build_ikev1_sa_payload(weak=True) -> bytes:
    """Build one SA payload containing one proposal with one transform."""
    if weak:
        t = _ikev1_transform(1, 1, enc=5, hsh=1, auth=1, grp=2)  # 3DES, MD5, PSK, DH2
    else:
        t = _ikev1_transform(1, 1, enc=7, hsh=4, auth=1, grp=14)  # AES, SHA2-256, PSK, DH14
    # transform header's "next payload" byte (offset 0) should be 0 (last transform)
    t = bytes([0]) + t[1:]
    prop_body = struct.pack(">BBBB", 1, 1, 0, 1) + t  # proposal#1, proto=ISAKMP(1), spi_size=0, 1 transform
    prop_len = 4 + len(prop_body)
    proposal = struct.pack(">BBH", 0, 0, prop_len) + prop_body  # next=0 (last proposal)
    sa_body = struct.pack(">II", 1, 1) + proposal  # DOI=IPSEC(1), Situation=SIT_IDENTITY_ONLY(1)
    return sa_body


def build_notify_payload(msg_type: int) -> bytes:
    # v1 layout: DOI(4) Proto(1) SPIsize(1) MsgType(2)
    return struct.pack(">IBBH", 1, 1, 0, msg_type)


def build_isakmp_message(init_spi_int, resp_spi_int, version, exch_type, flags, msg_id,
                          payloads: list):
    """payloads: list of (payload_type_code, body_bytes) in chain order."""
    init_spi = struct.pack(">Q", init_spi_int)
    resp_spi = struct.pack(">Q", resp_spi_int)
    chain = b""
    for i, (ptype, body) in enumerate(payloads):
        next_type = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        header = struct.pack(">BBH", next_type, 0, 4 + len(body))
        chain += header + body
    first_next = payloads[0][0] if payloads else 0
    total_len = 28 + len(chain)
    header = init_spi + resp_spi + struct.pack(">BBBBI", first_next, version, exch_type, flags, msg_id) + \
        struct.pack(">I", total_len)
    return header + chain


def generate_sample_pcap(path: str):
    random.seed(42)
    MAC_A = bytes.fromhex("00e0aabbcc01")
    MAC_B = bytes.fromhex("00e0aabbcc02")
    IP_A, IP_B = "203.0.113.10", "198.51.100.20"

    records = []  # (timestamp, raw_ethernet_frame)
    t = 1_725_000_000.0

    # --- Scenario 1: IKEv1 Main Mode (weak proposal) completing Phase 1 ---
    init_spi_1, resp_spi_1 = 0x1111111111111111, 0x0
    sa_body = build_ikev1_sa_payload(weak=True)
    msg1 = build_isakmp_message(init_spi_1, resp_spi_1, 0x10, 2, 0x00, 0, [(1, sa_body)])
    records.append((t, _eth_ip_udp(MAC_A, MAC_B, IP_A, IP_B, 500, 500, msg1))); t += 0.02

    resp_spi_1 = 0x2222222222222222
    msg2 = build_isakmp_message(init_spi_1, resp_spi_1, 0x10, 2, 0x00, 0, [(1, sa_body)])
    records.append((t, _eth_ip_udp(MAC_B, MAC_A, IP_B, IP_A, 500, 500, msg2))); t += 0.02

    for _ in range(4):  # KE/Nonce + ID/Hash round trips (empty bodies -- header only, simplified)
        msg = build_isakmp_message(init_spi_1, resp_spi_1, 0x10, 2, 0x00, 0, [])
        records.append((t, _eth_ip_udp(MAC_A, MAC_B, IP_A, IP_B, 500, 500, msg))); t += 0.02
        msg = build_isakmp_message(init_spi_1, resp_spi_1, 0x10, 2, 0x00, 0, [])
        records.append((t, _eth_ip_udp(MAC_B, MAC_A, IP_B, IP_A, 500, 500, msg))); t += 0.02

    # Phase 2 Quick Mode completing the tunnel
    qm_sa = build_ikev1_sa_payload(weak=True)
    msg = build_isakmp_message(init_spi_1, resp_spi_1, 0x10, 32, 0x01, 7, [(1, qm_sa)])
    records.append((t, _eth_ip_udp(MAC_A, MAC_B, IP_A, IP_B, 500, 500, msg))); t += 0.02
    msg = build_isakmp_message(init_spi_1, resp_spi_1, 0x10, 32, 0x01, 7, [(1, qm_sa)])
    records.append((t, _eth_ip_udp(MAC_B, MAC_A, IP_B, IP_A, 500, 500, msg))); t += 0.02

    # --- Scenario 2: IKEv1 Aggressive Mode -> NO_PROPOSAL_CHOSEN failure ---
    init_spi_2 = 0x3333333333333333
    sa_body2 = build_ikev1_sa_payload(weak=True)
    msg = build_isakmp_message(init_spi_2, 0x0, 0x10, 4, 0x00, 0, [(1, sa_body2)])
    records.append((t, _eth_ip_udp(MAC_A, MAC_B, IP_A, IP_B, 500, 500, msg))); t += 0.02

    resp_spi_2 = 0x4444444444444444
    notify_body = build_notify_payload(14)  # NO_PROPOSAL_CHOSEN
    msg = build_isakmp_message(init_spi_2, resp_spi_2, 0x10, 5, 0x00, 99, [(11, notify_body)])
    records.append((t, _eth_ip_udp(MAC_B, MAC_A, IP_B, IP_A, 500, 500, msg))); t += 0.02

    # --- Scenario 3: IKEv2 IKE_SA_INIT + IKE_AUTH (strong proposal, succeeds) ---
    init_spi_3 = 0x5555555555555555
    sa_v2 = build_ikev1_sa_payload(weak=False)  # reuse the walker's parseable shape isn't identical;
    # Build a minimal IKEv2-shaped SA (Proposal Substructure) instead:
    def ikev2_transform(ttype, tid):
        body = struct.pack(">BBH", ttype, 0, tid)
        tlen = 8
        return struct.pack(">BBH", 0, 0, tlen) + body
    transforms_v2 = b"".join([
        bytes([3]) + ikev2_transform(1, 18)[1:],   # ENCR=AES-GCM-16 (more transforms follow)
        bytes([3]) + ikev2_transform(3, 12)[1:],   # INTEG=HMAC-SHA2-256-128
        bytes([3]) + ikev2_transform(2, 5)[1:],    # PRF=PRF-HMAC-SHA2-256
        bytes([0]) + ikev2_transform(4, 14)[1:],   # D-H=DH14 (last transform)
    ])
    prop_body = struct.pack(">BBBB", 1, 1, 0, 4) + transforms_v2
    prop_len = 8 + len(prop_body) - 4
    proposal_v2 = struct.pack(">BBH", 0, 0, 4 + len(prop_body)) + prop_body
    sa_v2_body = proposal_v2

    msg = build_isakmp_message(init_spi_3, 0x0, 0x20, 34, 0x08, 0, [(33, sa_v2_body)])
    records.append((t, _eth_ip_udp(MAC_A, MAC_B, IP_A, IP_B, 500, 500, msg))); t += 0.02
    resp_spi_3 = 0x6666666666666666
    msg = build_isakmp_message(init_spi_3, resp_spi_3, 0x20, 34, 0x28, 0, [(33, sa_v2_body)])
    records.append((t, _eth_ip_udp(MAC_B, MAC_A, IP_B, IP_A, 500, 500, msg))); t += 0.02
    # IKE_AUTH (encrypted in reality -- flag SK bit so dissector reports "encrypted")
    msg = build_isakmp_message(init_spi_3, resp_spi_3, 0x20, 35, 0x09, 1, [])
    records.append((t, _eth_ip_udp(MAC_A, MAC_B, IP_A, IP_B, 500, 500, msg))); t += 0.02
    msg = build_isakmp_message(init_spi_3, resp_spi_3, 0x20, 35, 0x29, 1, [])
    records.append((t, _eth_ip_udp(MAC_B, MAC_A, IP_B, IP_A, 500, 500, msg))); t += 0.02

    # --- ESP traffic on SPI 0xC0FFEE01 with an out-of-order and a gapped packet ---
    spi = 0xC0FFEE01
    seqs = [1, 2, 3, 4, 6, 7, 5, 8, 9, 10]  # 5 missing then arrives late (OOO), gap before it
    for s in seqs:
        records.append((t, _eth_ip_esp(MAC_A, MAC_B, IP_A, IP_B, spi, s)))
        t += 0.01

    with open(path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for ts, frame in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)

    return path


if __name__ == "__main__":
    generate_sample_pcap("ipsec_demo.pcap")
    print("wrote ipsec_demo.pcap")
