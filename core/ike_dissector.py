"""
ike_dissector.py
Parses the ISAKMP common header (shared by IKEv1 and IKEv2, RFC 2408 / RFC 7296)
and walks the generic payload chain far enough to pull out:
  - Exchange type / message id / SPIs
  - Security Association proposals & transforms (cipher, hash, DH group, auth)
  - Notify payloads (error/status codes)
This is a best-effort educational dissector, not a full protocol stack.
"""
import struct
from dataclasses import dataclass, field
from typing import List, Optional


IKEV1_EXCHANGE_TYPES = {
    1: "Base Mode", 2: "Identity Protection (Main Mode)",
    3: "Authentication Only", 4: "Aggressive Mode",
    5: "Informational", 32: "Quick Mode", 33: "New Group Mode",
}
IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH",
    36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
}

# IKEv1 next-payload type codes (RFC 2408)
IKEV1_PAYLOAD = {
    0: "NONE", 1: "SA", 2: "Proposal", 3: "Transform", 4: "KE",
    5: "ID", 6: "CERT", 7: "CR", 8: "Hash", 9: "SIG", 10: "Nonce",
    11: "Notify", 12: "Delete", 13: "VendorID",
}
# IKEv2 next-payload type codes (RFC 7296)
IKEV2_PAYLOAD = {
    33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "VendorID",
    44: "TSi", 45: "TSr", 46: "Encrypted", 47: "CP", 48: "EAP",
}

IKEV1_ENCRYPTION_ALG = {
    1: "DES-CBC", 2: "IDEA-CBC", 3: "Blowfish-CBC", 4: "RC5-R16-B64-CBC",
    5: "3DES-CBC", 6: "CAST-CBC", 7: "AES-CBC",
}
IKEV1_HASH_ALG = {
    1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512",
}
IKEV1_DH_GROUP = {
    1: "DH1 (768-bit MODP)", 2: "DH2 (1024-bit MODP)", 5: "DH5 (1536-bit MODP)",
    14: "DH14 (2048-bit MODP)", 15: "DH15 (3072-bit MODP)",
    19: "DH19 (256-bit ECP)", 20: "DH20 (384-bit ECP)", 21: "DH21 (521-bit ECP)",
}
IKEV1_AUTH_METHOD = {
    1: "Pre-Shared Key", 3: "DSS Signatures", 4: "RSA Signatures",
    5: "RSA Encryption", 65001: "XAUTH", 65002: "Hybrid",
}

# IKEv2 Transform types & IDs (RFC 7296 / IANA)
IKEV2_TRANSFORM_TYPE = {1: "Encryption (ENCR)", 2: "PRF", 3: "Integrity (INTEG)",
                         4: "DH Group (D-H)", 5: "Extended Sequence Numbers (ESN)"}
IKEV2_ENCR_ID = {
    1: "DES-IV64", 2: "DES", 3: "3DES", 5: "CAST", 6: "Blowfish",
    12: "AES-CBC", 13: "AES-CTR", 18: "AES-GCM-16", 19: "AES-GCM-8",
    20: "AES-CCM-16", 28: "CHACHA20-POLY1305",
}
IKEV2_INTEG_ID = {
    1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 5: "AES-XCBC-96",
    12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256",
}
IKEV2_PRF_ID = {1: "PRF-HMAC-MD5", 2: "PRF-HMAC-SHA1", 5: "PRF-HMAC-SHA2-256",
                 6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512"}

NOTIFY_MESSAGE_TYPES = {
    1: "INVALID_PAYLOAD_TYPE", 7: "INVALID_SYNTAX",
    9: "INVALID_FLAGS", 11: "INVALID_COOKIE",
    14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KEY_INFORMATION",
    18: "INVALID_ID_INFORMATION", 24: "AUTHENTICATION_FAILED",
    34: "TS_UNACCEPTABLE", 36: "SINGLE_PAIR_REQUIRED",
    41: "NO_ADDITIONAL_SAS", 43: "INTERNAL_ADDRESS_FAILURE",
    44: "FAILED_CP_REQUIRED", 51: "UNSUPPORTED_CRITICAL_PAYLOAD",
}


@dataclass
class Transform:
    number: int
    proto_or_type: str
    algorithm: str
    detail: str = ""


@dataclass
class NotifyInfo:
    message_type: int
    message_name: str


@dataclass
class IsakmpMessage:
    packet_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    initiator_spi: str
    responder_spi: str
    version_major: int
    version_minor: int
    exchange_type: int
    exchange_name: str
    is_response: bool
    is_encrypted: bool
    message_id: int
    length: int
    transforms: List[Transform] = field(default_factory=list)
    notifies: List[NotifyInfo] = field(default_factory=list)
    parse_note: str = ""


def _payload_name(is_v2: bool, code: int) -> str:
    table = IKEV2_PAYLOAD if is_v2 else IKEV1_PAYLOAD
    return table.get(code, f"Unknown(0x{code:02x})")


def _parse_ikev1_transform_attrs(attr_bytes: bytes):
    """Walk IKEv1 SA attribute TLVs (RFC 2408 sec 3.3)."""
    attrs = {}
    off = 0
    while off + 4 <= len(attr_bytes):
        af_type = struct.unpack(">H", attr_bytes[off:off + 2])[0]
        af = af_type >> 15
        atype = af_type & 0x7FFF
        if af == 1:  # TV -- 2-byte value packed in the length field
            value = struct.unpack(">H", attr_bytes[off + 2:off + 4])[0]
            attrs[atype] = value
            off += 4
        else:  # TLV
            if off + 4 > len(attr_bytes):
                break
            alen = struct.unpack(">H", attr_bytes[off + 2:off + 4])[0]
            value_bytes = attr_bytes[off + 4:off + 4 + alen]
            if alen <= 4:
                value = int.from_bytes(value_bytes, "big") if value_bytes else 0
            else:
                value = value_bytes
            attrs[atype] = value
            off += 4 + alen
    return attrs


def _parse_ikev1_sa_payload(body: bytes) -> List[Transform]:
    """body is the SA payload content *after* the 4-byte generic header,
    i.e. starts with DOI(4) + Situation(4), followed by Proposal payloads."""
    transforms: List[Transform] = []
    if len(body) < 8:
        return transforms
    pos = 8  # skip DOI + Situation
    while pos + 8 <= len(body):
        next_p, _reserved, prop_len = struct.unpack(">BBH", body[pos:pos + 4])
        prop_num, proto_id, spi_size, num_transforms = struct.unpack(
            ">BBBB", body[pos + 4:pos + 8]
        )
        prop_body_start = pos + 8 + spi_size
        prop_end = pos + prop_len
        if prop_len < 8 or prop_end > len(body):
            break
        # Walk transform payloads inside this proposal
        tpos = prop_body_start
        while tpos + 8 <= prop_end:
            t_next, _tres, t_len = struct.unpack(">BBH", body[tpos:tpos + 4])
            t_num, t_id, _t_res2 = struct.unpack(">BBH", body[tpos + 4:tpos + 8])
            attr_bytes = body[tpos + 8: tpos + t_len] if t_len >= 8 else b""
            attrs = _parse_ikev1_transform_attrs(attr_bytes)
            enc = IKEV1_ENCRYPTION_ALG.get(attrs.get(1), None)
            hsh = IKEV1_HASH_ALG.get(attrs.get(2), None)
            auth = IKEV1_AUTH_METHOD.get(attrs.get(3), None)
            grp = IKEV1_DH_GROUP.get(attrs.get(4), None)
            parts = []
            if enc:
                parts.append(f"Encryption={enc}")
            if hsh:
                parts.append(f"Hash={hsh}")
            if auth:
                parts.append(f"Auth={auth}")
            if grp:
                parts.append(f"Group={grp}")
            transforms.append(Transform(
                number=t_num,
                proto_or_type=f"Proposal {prop_num} / Transform {t_num} (proto {proto_id})",
                algorithm=", ".join(parts) if parts else f"raw-transform-id={t_id}",
            ))
            if t_len < 8:
                break
            tpos += t_len
            if t_next == 0:
                break
        pos += prop_len
        if next_p == 0:
            break
    return transforms


def _parse_ikev2_sa_payload(body: bytes) -> List[Transform]:
    """body is the SA payload content after the 4-byte generic header, i.e.
    a sequence of Proposal Substructures (RFC 7296 sec 3.3)."""
    transforms: List[Transform] = []
    pos = 0
    while pos + 8 <= len(body):
        last2, _res, plen = struct.unpack(">BBH", body[pos:pos + 4])
        prop_num, proto_id, spi_size, num_t = struct.unpack(">BBBB", body[pos + 4:pos + 8])
        if plen < 8 or pos + plen > len(body):
            break
        tpos = pos + 8 + spi_size
        prop_end = pos + plen
        while tpos + 8 <= prop_end:
            last, _r, tlen = struct.unpack(">BBH", body[tpos:tpos + 4])
            ttype, _r2, tid = struct.unpack(">BBH", body[tpos + 4:tpos + 8])
            algo = "?"
            if ttype == 1:
                algo = IKEV2_ENCR_ID.get(tid, f"ENCR-id-{tid}")
            elif ttype == 2:
                algo = IKEV2_PRF_ID.get(tid, f"PRF-id-{tid}")
            elif ttype == 3:
                algo = IKEV2_INTEG_ID.get(tid, f"INTEG-id-{tid}")
            elif ttype == 4:
                algo = IKEV1_DH_GROUP.get(tid, f"DH-group-{tid}")
            elif ttype == 5:
                algo = "ESN" if tid == 1 else "No-ESN"
            transforms.append(Transform(
                number=prop_num,
                proto_or_type=f"Proposal {prop_num} / {IKEV2_TRANSFORM_TYPE.get(ttype, f'Type{ttype}')}",
                algorithm=algo,
            ))
            if tlen < 8:
                break
            tpos += tlen
            if last == 0:
                break
        pos += plen
        if last2 == 0:
            break
    return transforms


def _parse_notify_payload(body: bytes) -> Optional[NotifyInfo]:
    # Generic Notify payload (post generic-header body):
    # DOI(4, v1 only) / Protocol-ID(1) SPI-Size(1) Notify-Msg-Type(2) [v2: Protocol-ID(1) SPI-Size(1) Type(2)]
    # We branch on length heuristically since v1 has an extra DOI field.
    if len(body) >= 8:
        # try v1 layout: DOI(4) Proto(1) SPIsize(1) MsgType(2)
        _doi, proto, spisize, msgtype = struct.unpack(">IBBH", body[0:8])
        if msgtype in NOTIFY_MESSAGE_TYPES:
            return NotifyInfo(msgtype, NOTIFY_MESSAGE_TYPES[msgtype])
    if len(body) >= 4:
        proto, spisize, msgtype = struct.unpack(">BBH", body[0:4])
        return NotifyInfo(msgtype, NOTIFY_MESSAGE_TYPES.get(msgtype, f"Unknown ({msgtype})"))
    return None


def parse_isakmp(packet_index: int, timestamp: float, src_ip: str, dst_ip: str,
                  src_port: int, dst_port: int, payload: bytes) -> Optional[IsakmpMessage]:
    if len(payload) < 28:
        return None

    init_spi = payload[0:8].hex()
    resp_spi = payload[8:16].hex()
    next_payload, version, exch_type, flags = struct.unpack(">BBBB", payload[16:20])
    message_id = struct.unpack(">I", payload[20:24])[0]
    length = struct.unpack(">I", payload[24:28])[0]

    ver_major = version >> 4
    ver_minor = version & 0x0F
    is_v2 = ver_major == 2
    is_response = bool(flags & 0x20) if is_v2 else bool(flags & 0x02)  # v2 bit3=Response; v1 bit1=Commit(approx use)
    is_encrypted = bool(flags & 0x01)

    exch_table = IKEV2_EXCHANGE_TYPES if is_v2 else IKEV1_EXCHANGE_TYPES
    exch_name = exch_table.get(exch_type, f"Unknown ({exch_type})")

    msg = IsakmpMessage(
        packet_index=packet_index, timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        initiator_spi=init_spi, responder_spi=resp_spi,
        version_major=ver_major, version_minor=ver_minor,
        exchange_type=exch_type, exchange_name=exch_name,
        is_response=is_response, is_encrypted=is_encrypted,
        message_id=message_id, length=length,
    )

    if is_encrypted:
        msg.parse_note = ("Payloads are encrypted (SK/Hash payload present) -- "
                           "inner content requires session keys to inspect.")
        return msg

    # Walk the generic payload chain starting right after the 28-byte header
    pos = 28
    cur_payload_type = next_payload
    guard = 0
    while cur_payload_type != 0 and pos + 4 <= len(payload) and guard < 64:
        guard += 1
        gp_next, _res, gp_len = struct.unpack(">BBH", payload[pos:pos + 4])
        if gp_len < 4 or pos + gp_len > len(payload):
            msg.parse_note += " [payload chain truncated]"
            break
        body = payload[pos + 4: pos + gp_len]

        pname = _payload_name(is_v2, cur_payload_type)
        if pname == "SA":
            if is_v2:
                msg.transforms.extend(_parse_ikev2_sa_payload(body))
            else:
                msg.transforms.extend(_parse_ikev1_sa_payload(body))
        elif pname == "Notify":
            n = _parse_notify_payload(body)
            if n:
                msg.notifies.append(n)

        pos += gp_len
        cur_payload_type = gp_next

    return msg
