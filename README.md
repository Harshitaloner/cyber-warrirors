# IPsec VPN Protocol Analyser & Security Forensics Framework
### Hackathon MVP prototype (Problem Statement: IPsec VPN Protocol Analyser)

A Streamlit application that ingests a `.pcap` capture, reconstructs IKEv1/IKEv2
handshake state machines, audits proposed cryptographic algorithms against a
compliance rulebase, explains *why* a tunnel failed in plain English, and
analyses ESP sequence numbers for anti-replay / packet-loss issues.

Built with **only Python's standard library at the core** (a hand-written
PCAP reader and ISAKMP/IKE dissector) plus Streamlit for the UI, pandas for
tables, and ReportLab for the PDF report — no `scapy`, `pyshark`, or system
`tshark` install required, so it runs anywhere Python runs.

---

## 1. What's inside

```
ipsec_analyser/
├── app.py                     # Streamlit UI (7 tabs)
├── requirements.txt
├── core/
│   ├── pcap_reader.py          # classic .pcap file parser (stdlib only)
│   ├── packet_dissector.py     # Ethernet/IP/UDP/ESP/AH layer stripping
│   ├── ike_dissector.py        # ISAKMP header + IKEv1/IKEv2 SA/Proposal/
│   │                           # Transform/Notify payload parsing
│   ├── crypto_audit.py         # weak-cipher / weak-DH / weak-hash rulebase
│   ├── state_engine.py         # SPI correlation -> tunnel sessions,
│   │                           # ESP sequence-number anti-replay analysis
│   ├── diagnostics.py          # plain-English root-cause explanations
│   ├── report_generator.py     # PDF audit report (ReportLab)
│   └── sample_pcap_generator.py# crafts a synthetic demo capture, no
│                                # external tools needed
└── sample_captures/
    └── ipsec_demo.pcap         # generated on first run if missing
```

## 2. What the sample capture demonstrates

So the demo works instantly even without a real capture on hand, the app can
generate a synthetic-but-structurally-valid `.pcap` containing:

1. An **IKEv1 Main Mode** tunnel negotiated with a **weak proposal**
   (3DES / MD5 / DH Group 2) that completes successfully → flagged as
   critical findings in the Crypto Audit tab.
2. An **IKEv1 Aggressive Mode** negotiation that the responder **rejects**
   with `NO_PROPOSAL_CHOSEN` → shown with a root-cause explanation in
   Diagnostics.
3. A **strong IKEv2** tunnel (AES-GCM / SHA2-256 / DH14) that completes
   cleanly → shown as "Established" with a clean crypto profile.
4. A run of **ESP packets** on one SPI with one out-of-order and one
   gapped sequence number → picked up by the anti-replay analysis tab.

You can swap this for a real capture at any time from the sidebar.

## 3. Step-by-step: run it locally

**Prerequisite:** Python 3.9+ installed.

### Step 1 — Get the files
Unzip the project folder anywhere, e.g. `~/ipsec_analyser`.

### Step 2 — (Recommended) create a virtual environment
```bash
cd ipsec_analyser
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Launch the app
```bash
streamlit run app.py
```

### Step 5 — Open it
Streamlit prints a local URL, normally:
```
Local URL: http://localhost:8501
```
Open it in your browser (it usually opens automatically).

### Step 6 — Try it out
- Leave **"Use bundled sample capture"** selected in the sidebar to see the
  full demo immediately (no upload needed), **or**
- Select **"Upload a .pcap file"** and drop in your own classic `.pcap`
  capture of an IPsec negotiation (e.g. exported from Wireshark:
  *File → Export Specified Packets → .pcap*, **not** `.pcapng`).
- Walk through the tabs: **Overview → Handshake Timeline → Crypto Audit →
  Diagnostics → ESP/Anti-Replay → Packets → Report**.
- Click **Download PDF report** on the last tab for a shareable audit
  report.

## 4. Presenting it at the hackathon

Suggested demo flow (≈3 minutes):
1. **Overview tab** — show the posture score/grade dashboard at a glance.
2. **Handshake Timeline** — point out the IKEv1 tunnel that *did* establish
   despite negotiating 3DES/MD5, versus the IKEv2 tunnel using AES-GCM.
3. **Crypto Audit** — show the automatically generated critical findings
   with plain-English explanations (this is the "compliance auditing"
   pillar from the problem statement).
4. **Diagnostics** — click into the failed `NO_PROPOSAL_CHOSEN` session and
   read out the root-cause explanation — this is the "converts binary
   notify codes into explicit root-cause diagnosis" capability called out
   in the brief.
5. **ESP/Anti-Replay** — show the detected gap and out-of-order packet on
   the ESP flow.
6. **Report tab** — download the PDF live to show the compliance-audit
   output artifact.

## 5. Known MVP limitations (be upfront about these if asked)

- Parses **classic `.pcap`** files only; `.pcapng` must be re-exported from
  Wireshark first (mentioned in-app if a pcapng file is uploaded).
- IKEv2 payloads inside `SK` (encrypted) containers cannot be inspected
  without session keys — the app correctly reports these as encrypted
  rather than guessing at their contents. Phase 2 of the roadmap
  (key-assisted ESP/IKE decryption) targets this.
- NAT-Traversal (UDP 4500) framing and basic ESP SPI/sequence tracking are
  implemented; full stateful re-key correlation is a Phase 2/3 item per the
  roadmap in the problem statement brief.
- This is a diagnostic/audit aid, not a certified compliance tool — the
  PDF report says so explicitly.

## 6. Extending it after the hackathon

- Swap `pcap_reader.py` for `pyshark`/`dpkt` to add live-interface capture
  and `.pcapng` support (Phase 2 of the brief's roadmap).
- Add a rules file (YAML/JSON) for `crypto_audit.py` so the compliance
  rulebase can be swapped between NIST / CNSA 2.0 / PCI-DSS profiles.
- Add key-file import + `cryptography`/`OpenSSL` bindings for ESP payload
  decryption (Phase 2).
- Add a Mermaid.js/D3.js sequence-diagram renderer for the Handshake
  Timeline tab (currently a structured table) for a closer match to the
  original brief's "visual sequence diagram generator".
