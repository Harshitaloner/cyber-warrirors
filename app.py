"""
IPsec VPN Protocol Analyser & Security Forensics Framework
Hackathon MVP -- Streamlit front-end.

Run with:  streamlit run app.py
"""
import os
import tempfile
import pandas as pd
import streamlit as st

from core.pcap_reader import read_pcap, PcapParseError, linktype_name
from core.packet_dissector import parse_packet
from core.ike_dissector import parse_isakmp
from core.state_engine import build_sessions, analyse_esp
from core.crypto_audit import audit_messages, score_posture
from core.diagnostics import explain_session
from core.report_generator import build_pdf_report
from core.sample_pcap_generator import generate_sample_pcap

st.set_page_config(
    page_title="IPsec VPN Protocol Analyser",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------- styling --
st.markdown("""
<style>
.big-metric { font-size: 2rem; font-weight: 700; }
.grade-A { color: #16A34A; } .grade-B { color: #CA8A04; }
.grade-C { color: #EA580C; } .grade-D { color: #DC2626; }
.finding-critical { border-left: 4px solid #DC2626; padding: 8px 12px; margin-bottom: 8px; background: #FEF2F2; border-radius: 4px;}
.finding-warning  { border-left: 4px solid #D97706; padding: 8px 12px; margin-bottom: 8px; background: #FFFBEB; border-radius: 4px;}
.session-ok  { border-left: 4px solid #16A34A; padding: 10px 14px; margin-bottom: 10px; background: #F0FDF4; border-radius: 4px;}
.session-bad { border-left: 4px solid #DC2626; padding: 10px 14px; margin-bottom: 10px; background: #FEF2F2; border-radius: 4px;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ IPsec VPN Protocol Analyser")
st.caption("Cyber Security & Network Forensics · IKEv1/IKEv2 handshake dissection, "
           "cryptographic audit, and ESP anti-replay analysis -- from a raw PCAP.")


# ---------------------------------------------------------------- sidebar --
with st.sidebar:
    st.header("Input")
    source = st.radio("Choose a data source", ["Use bundled sample capture", "Upload a .pcap file"])

    uploaded_path = None
    label = "ipsec_demo.pcap (sample)"
    if source == "Upload a .pcap file":
        up = st.file_uploader("Classic .pcap (not .pcapng)", type=["pcap"])
        if up is not None:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
            tmp.write(up.getvalue())
            tmp.close()
            uploaded_path = tmp.name
            label = up.name
    else:
        sample_path = os.path.join("sample_captures", "ipsec_demo.pcap")
        if not os.path.exists(sample_path):
            generate_sample_pcap(sample_path)
        uploaded_path = sample_path

    st.markdown("---")
    st.caption(
        "The bundled sample contains a weak-cipher IKEv1 tunnel, a rejected "
        "negotiation (NO_PROPOSAL_CHOSEN), a strong IKEv2 tunnel, and an ESP "
        "flow with an out-of-order and a gapped sequence number -- so every "
        "part of the analyser has something to show."
    )
    st.markdown("---")
    st.caption("Phase 1 MVP -- offline PCAP dissection only. Live capture, "
               "key-assisted ESP decryption, and SIEM export are on the roadmap.")


if not uploaded_path:
    st.info("Upload a .pcap file or use the bundled sample from the sidebar to begin.")
    st.stop()


# ---------------------------------------------------------------- pipeline --
@st.cache_data(show_spinner=False)
def run_pipeline(path: str, mtime: float):
    packets, linktype = read_pcap(path)
    dissected = [parse_packet(p.index, p.timestamp, p.data, linktype) for p in packets]
    dissected = [d for d in dissected if d]

    isakmp_msgs = []
    for d in dissected:
        if d.kind == "isakmp":
            m = parse_isakmp(d.index, d.timestamp, d.src_ip, d.dst_ip,
                              d.src_port, d.dst_port, d.payload)
            if m:
                isakmp_msgs.append(m)

    sessions = build_sessions(isakmp_msgs)
    findings = audit_messages(isakmp_msgs)
    score = score_posture(findings)
    esp_flows = analyse_esp(dissected)
    return dict(
        linktype=linktype, dissected=dissected, isakmp_msgs=isakmp_msgs,
        sessions=sessions, findings=findings, score=score, esp_flows=esp_flows,
    )


try:
    result = run_pipeline(uploaded_path, os.path.getmtime(uploaded_path))
except PcapParseError as e:
    st.error(str(e))
    st.stop()
except Exception as e:
    st.error(f"Could not parse this capture: {e}")
    st.stop()

dissected = result["dissected"]
isakmp_msgs = result["isakmp_msgs"]
sessions = result["sessions"]
findings = result["findings"]
score = result["score"]
esp_flows = result["esp_flows"]

grade_letter = score["grade"][0]

# ---------------------------------------------------------------- overview --
tabs = st.tabs([
    "📊 Overview", "🔄 Handshake Timeline", "🔐 Crypto Audit",
    "🩺 Diagnostics", "📡 ESP / Anti-Replay", "🧾 Packets", "📄 Report",
])

with tabs[0]:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets analysed", len(dissected))
    c2.metric("ISAKMP messages", len(isakmp_msgs))
    c3.metric("Tunnel sessions", len(sessions))
    established = sum(1 for s in sessions if s.established)
    c4.metric("Established / Failed", f"{established} / {len(sessions) - established}")

    st.markdown("### Cryptographic Posture")
    cc1, cc2 = st.columns([1, 3])
    with cc1:
        st.markdown(
            f'<div class="big-metric grade-{grade_letter}">{score["grade"]}</div>',
            unsafe_allow_html=True,
        )
        st.progress(score["score"] / 100)
        st.caption(f'Score: {score["score"]}/100')
    with cc2:
        st.metric("Critical findings", score["critical"])
        st.metric("Warning findings", score["warning"])

    st.markdown("### Link layer")
    st.caption(f"Detected link type: {linktype_name(result['linktype'])}")

with tabs[1]:
    st.subheader("IKE Handshake Timeline")
    if not sessions:
        st.info("No ISAKMP (UDP 500/4500) traffic found in this capture.")
    for s in sessions:
        badge = "✅ Established" if s.established else "❌ Failed / Incomplete"
        css = "session-ok" if s.established else "session-bad"
        st.markdown(
            f'<div class="{css}"><b>{s.ike_version}</b> tunnel &nbsp;'
            f'<code>{s.peer_a}</code> ⇄ <code>{s.peer_b}</code> &nbsp;— {badge}</div>',
            unsafe_allow_html=True,
        )
        rows = []
        for m in s.messages:
            direction = f"{m.src_ip} → {m.dst_ip}"
            algo_summary = "; ".join(t.algorithm for t in m.transforms) if m.transforms else (
                "(encrypted)" if m.is_encrypted else "")
            notify_summary = ", ".join(n.message_name for n in m.notifies)
            rows.append({
                "Packet #": m.packet_index,
                "Direction": direction,
                "Exchange": m.exchange_name,
                "Msg ID": m.message_id,
                "Proposals / Algorithms": algo_summary,
                "Notify": notify_summary,
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        with st.expander("Root-cause explanation"):
            for line in explain_session(s):
                st.write("•", line)
        st.markdown("")

with tabs[2]:
    st.subheader("Cryptographic Proposal Audit")
    if not findings:
        st.success("No weak algorithms or negotiation errors detected.")
    else:
        for f in findings:
            css = "finding-critical" if f.severity == "critical" else "finding-warning"
            st.markdown(
                f'<div class="{css}"><b>[{f.severity.upper()}] {f.title}</b> '
                f'<i>(packet #{f.source_packet})</i><br>{f.detail}</div>',
                unsafe_allow_html=True,
            )

    st.markdown("### All negotiated transforms")
    tf_rows = []
    for m in isakmp_msgs:
        for t in m.transforms:
            tf_rows.append({
                "Packet #": m.packet_index, "IKE": f"v{m.version_major}",
                "Exchange": m.exchange_name, "Proposal/Type": t.proto_or_type,
                "Algorithm": t.algorithm,
            })
    if tf_rows:
        st.dataframe(pd.DataFrame(tf_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No cleartext SA/Proposal payloads found (traffic may be fully encrypted).")

with tabs[3]:
    st.subheader("Failure Diagnostics")
    failed = [s for s in sessions if not s.established]
    if not failed:
        st.success("Every tunnel in this capture negotiated successfully.")
    for s in failed:
        st.markdown(f"**{s.ike_version} tunnel** `{s.peer_a}` ⇄ `{s.peer_b}`")
        for line in explain_session(s):
            st.warning(line)

with tabs[4]:
    st.subheader("ESP Flow Health / Anti-Replay Analysis")
    if not esp_flows:
        st.info("No ESP (IP protocol 50) traffic found in this capture.")
    else:
        esp_rows = []
        for spi, fl in esp_flows.items():
            esp_rows.append({
                "SPI": spi, "Packets": fl.packets_seen,
                "Out-of-order": fl.out_of_order, "Gaps detected": fl.gaps_detected,
                "Max gap size": fl.max_gap, "Replay suspects": fl.replay_suspects,
            })
        st.dataframe(pd.DataFrame(esp_rows), use_container_width=True, hide_index=True)
        for spi, fl in esp_flows.items():
            if fl.gaps_detected or fl.out_of_order or fl.replay_suspects:
                st.warning(
                    f"SPI `{spi}`: {fl.gaps_detected} sequence gap(s) (max {fl.max_gap} "
                    f"packet(s) missing), {fl.out_of_order} out-of-order packet(s), "
                    f"{fl.replay_suspects} possible replay(s)."
                )
            else:
                st.success(f"SPI `{spi}`: clean sequence, no loss/replay detected.")

with tabs[5]:
    st.subheader("Raw Packet Inventory")
    prows = []
    for d in dissected:
        prows.append({
            "Index": d.index, "Time": round(d.timestamp, 3), "Src": d.src_ip,
            "Dst": d.dst_ip, "SrcPort": d.src_port, "DstPort": d.dst_port,
            "IP Proto": d.ip_proto, "Kind": d.kind, "Bytes": d.length,
        })
    st.dataframe(pd.DataFrame(prows), use_container_width=True, hide_index=True)

with tabs[6]:
    st.subheader("Audit Report")
    st.write("Generate a PDF summarising tunnel sessions, cryptographic findings, "
             "and ESP flow health -- suitable for attaching to an incident ticket "
             "or compliance review.")
    pdf_bytes = build_pdf_report(sessions, findings, score, esp_flows, source_name=label)
    st.download_button(
        "⬇️ Download PDF report", data=pdf_bytes,
        file_name="ipsec_audit_report.pdf", mime="application/pdf",
    )

st.markdown("---")
st.caption(
    "IPsec VPN Protocol Analyser — hackathon MVP prototype. Pure-Python "
    "PCAP/ISAKMP dissection, no scapy/pyshark/tshark dependency required."
)
