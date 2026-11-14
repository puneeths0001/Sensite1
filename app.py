import html, io
import pandas as pd
import streamlit as st
from detector import scan, risk, redact, add_block, verify_chain
from demo_data import DEMO_DOCS

st.set_page_config(page_title="Sensite | Sensitive Data Detection", page_icon="🛡️", layout="wide")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600&display=swap');
html, body, [class*="css"], .stApp {font-family:'Outfit',sans-serif !important;}
header[data-testid="stHeader"], footer, #MainMenu {display:none;}
.block-container {max-width:1180px; padding-top:1.2rem;}
.hero {position:relative; overflow:hidden; border-radius:34px; padding:26px 30px 70px; text-align:center;
  background: radial-gradient(70% 90% at 92% 20%, #ff4a1c 0%, rgba(255,74,28,0) 55%),
              radial-gradient(60% 80% at 8% 90%, #d9d9de 0%, rgba(217,217,222,0) 60%),
              linear-gradient(135deg,#f6f6f8,#e4e4e8);}
.nav {display:inline-flex; gap:26px; align-items:center; background:#fff; border-radius:999px; padding:10px 14px 10px 22px;
  box-shadow:0 6px 24px rgba(0,0,0,.08); font-size:14px; margin-bottom:56px;}
.nav b {font-weight:600; margin-right:10px;} .nav span {color:#555;}
.nav .btn {background:#16161a; color:#fff; padding:9px 18px; border-radius:999px;}
.pill {display:inline-block; font-size:12px; color:#ff4a1c; background:#fff; border:1px solid #ffd2c6; border-radius:8px; padding:4px 10px; margin-bottom:18px;}
.hero h1 {font-size:56px; font-weight:400; line-height:1.08; margin:0 0 16px; color:#16161a; letter-spacing:-1px;}
.hero p {color:#555; font-size:16px; max-width:520px; margin:0 auto 26px;}
.hero .b1 {background:#16161a; color:#fff; padding:12px 24px; border-radius:999px; margin-right:8px; display:inline-block;}
.hero .b2 {background:#fff; color:#16161a; padding:12px 24px; border-radius:999px; display:inline-block; box-shadow:0 4px 14px rgba(0,0,0,.08);}
.tag {display:inline-block; font-size:12px; color:#ff4a1c; background:#fff; border:1px solid #ffd2c6; border-radius:8px; padding:3px 10px; margin:36px 0 8px;}
h2.sec {font-size:40px; font-weight:400; letter-spacing:-.8px; margin:0 0 18px; color:#16161a;}
.card {background:#fff; border-radius:28px; padding:26px; box-shadow:0 8px 28px rgba(0,0,0,.06);}
.dark {background:linear-gradient(160deg,#26262b,#101013); color:#fff; border-radius:28px; padding:26px;}
.big {font-size:84px; font-weight:300; line-height:1; letter-spacing:-3px;}
.lvl {font-size:22px; font-weight:500;}
.muted {color:#8a8a92; font-size:14px;}
.stat {font-size:44px; font-weight:300; letter-spacing:-1.5px; color:#16161a;}
.docview {background:#fff; border-radius:28px; padding:22px 26px; white-space:pre-wrap; font-size:15px; line-height:1.8; box-shadow:0 8px 28px rgba(0,0,0,.06);}
mark {background:#ffe1d8; color:#c2300c; border-radius:6px; padding:1px 6px; font-weight:500;}
mark small {font-size:10px; margin-left:5px; opacity:.75; font-weight:400;}
.block {background:#1d1d22; border-radius:16px; padding:12px 16px; margin-bottom:10px; font-size:13px; color:#cfcfd6;}
.block code {color:#ff7a57; background:transparent;}
.foot {text-align:center; color:#8a8a92; font-size:13px; margin:44px 0 10px;}
.stButton>button, .stDownloadButton>button {border-radius:999px; background:#16161a; color:#fff; border:0; padding:.55rem 1.4rem;}
.stButton>button:hover, .stDownloadButton>button:hover {background:#ff4a1c; color:#fff;}
@media (max-width:700px){.hero h1{font-size:36px}.nav span{display:none}.big{font-size:60px}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <div class="nav"><b>Sensite</b><span>Scan</span><span>Results</span><span>Ledger</span><div class="btn">CB-02</div></div><br>
  <div class="pill">Intelligent Data Loss Prevention</div>
  <h1>Find sensitive data<br>before it leaks.</h1>
  <p>Upload a document and Sensite detects personal, financial and credential data, scores the risk, redacts it, and logs every scan on a tamper-evident ledger.</p>
  <span class="b1">Scan a document</span><span class="b2">Try demo data</span>
</div>""", unsafe_allow_html=True)

# ---------- Input ----------
st.markdown('<div class="tag">Scan</div><h2 class="sec">Choose a document</h2>', unsafe_allow_html=True)
src = st.radio("Source", ["Demo document", "Paste text", "Upload file"], horizontal=True, label_visibility="collapsed")

def read_upload(f) -> str:
    name = f.name.lower()
    if name.endswith(".pdf"):
        from pypdf import PdfReader
        return "\n".join(p.extract_text() or "" for p in PdfReader(f).pages)
    if name.endswith(".docx"):
        from docx import Document
        return "\n".join(p.text for p in Document(f).paragraphs)
    return f.read().decode("utf-8", errors="ignore")

doc_name, text = "", ""
if src == "Demo document":
    doc_name = st.selectbox("Pick a demo", list(DEMO_DOCS))
    text = DEMO_DOCS[doc_name]
elif src == "Paste text":
    doc_name = "Pasted text"
    text = st.text_area("Paste text", height=200, placeholder="Paste any text containing emails, phone numbers, card numbers...")
else:
    up = st.file_uploader("Upload a .txt, .csv, .pdf or .docx file", type=["txt", "csv", "md", "pdf", "docx"])
    if up:
        doc_name, text = up.name, read_upload(up)

mode_label = st.radio("Redaction style", ["Partial mask (keep last 4)", "Full label"], horizontal=True)
mode = "mask" if mode_label.startswith("Partial") else "label"

if "chain" not in st.session_state:
    st.session_state.chain, st.session_state.last = [], None

if st.button("Scan document") and text.strip():
    f = scan(text); s, l = risk(f)
    add_block(st.session_state.chain, doc_name, f, s)
    st.session_state.last = (doc_name, text)

# ---------- Results ----------
if st.session_state.last:
    name, txt = st.session_state.last
    findings = scan(txt); score, level = risk(findings)
    st.markdown('<div class="tag">Results</div><h2 class="sec">What we found</h2>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1.3, 1, 1])
    c1.markdown(f'<div class="dark"><div class="muted">Risk score for {html.escape(name)}</div>'
                f'<div class="big">{score}</div><div class="lvl" style="color:#ff7a57">{level} risk</div></div>', unsafe_allow_html=True)
    c2.markdown(f'<div class="card"><div class="muted">Items detected</div><div class="stat">{len(findings)}</div></div>', unsafe_allow_html=True)
    cats = len({f.category for f in findings})
    c3.markdown(f'<div class="card"><div class="muted">Categories affected</div><div class="stat">{cats}</div></div>', unsafe_allow_html=True)

    if not findings:
        st.success("No sensitive information detected in this document.")
    else:
        st.write("")
        # highlighted document
        parts, last = [], 0
        for f in findings:
            parts.append(html.escape(txt[last:f.start]))
            parts.append(f"<mark>{html.escape(f.value)}<small>{f.type}</small></mark>")
            last = f.end
        parts.append(html.escape(txt[last:]))
        st.markdown('<div class="docview">' + "".join(parts) + "</div>", unsafe_allow_html=True)

        st.write("")
        df = pd.DataFrame([{"Type": f.type, "Category": f.category, "Severity": ["", "Low", "Medium", "High", "Critical"][f.severity],
                            "Found": f.value, "Masked": redact(f.value, [type(f)(f.type, f.category, f.severity, f.value, 0, len(f.value))], mode)}
                           for f in findings])
        a, b = st.columns([1.4, 1])
        a.dataframe(df, use_container_width=True, hide_index=True)
        b.bar_chart(df["Category"].value_counts(), color="#ff4a1c")

        st.markdown('<div class="tag">Output</div><h2 class="sec">Redacted copy</h2>', unsafe_allow_html=True)
        red = redact(txt, findings, mode)
        st.code(red, language=None)
        d1, d2 = st.columns(2)
        d1.download_button("Download redacted text", red, file_name="redacted.txt")
        d2.download_button("Download findings (CSV)", df.drop(columns=["Found"]).to_csv(index=False), file_name="findings.csv")

# ---------- Ledger ----------
st.markdown('<div class="tag">Audit</div><h2 class="sec">Scan ledger</h2>', unsafe_allow_html=True)
chain = st.session_state.chain
if not chain:
    st.markdown('<div class="card muted">No scans yet. Scan a document and each result is added here as a hash-linked block.</div>', unsafe_allow_html=True)
else:
    ok = verify_chain(chain)
    st.markdown(f'<div class="dark"><div class="lvl">Chain integrity: <span style="color:{"#5be37d" if ok else "#ff4a1c"}">{"Verified" if ok else "Tampered"}</span></div>'
                f'<div class="muted" style="margin-bottom:14px">Each block stores the SHA-256 hash of the one before it, so edits to past records are detectable.</div>' +
                "".join(f'<div class="block">Block {b["index"]} at {b["time"]} · {html.escape(b["document"])} · {b["findings"]} items · risk {b["risk"]}<br>'
                        f'hash <code>{b["hash"][:32]}…</code> prev <code>{b["prev"][:12]}…</code></div>' for b in reversed(chain)) + '</div>',
                unsafe_allow_html=True)

st.markdown('<div class="foot">Sensite · HackShastra 2K26 · Problem statement CB-02. Demo data is synthetic.</div>', unsafe_allow_html=True)
