import html
import streamlit as st
from detector import scan, redact, mask_value
from demo_data import DEMO_DOCS

st.set_page_config(page_title="Sensite | Sensitive Data Detection", page_icon="🛡️", layout="wide")
ss = st.session_state
ss.setdefault("src", "Demo document")
ss.setdefault("demo_pick", list(DEMO_DOCS)[0])

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600&display=swap');
:root{--ink:#16161a;--acc:#ff4a1c;}
html,body,.stApp,.stApp *{font-family:'Outfit',sans-serif;}
.stApp [data-testid="stIconMaterial"],.stApp span[class*="material"],.stApp [data-testid="stExpander"] summary [data-testid="stIconMaterial"]{font-family:'Material Symbols Rounded','Material Symbols Outlined' !important;font-weight:400 !important;}
.stApp,[data-testid="stAppViewContainer"],[data-testid="stMain"]{background:#ececec !important;color:var(--ink) !important;}
header[data-testid="stHeader"],footer,#MainMenu,[data-testid="stToolbar"]{display:none !important;}
.block-container{max-width:1160px;padding-top:1rem;}
.stApp [data-testid="stMarkdownContainer"],.stApp [data-testid="stMarkdownContainer"] p,.stApp label,.stApp label *,.stApp [data-testid="stWidgetLabel"] *{color:var(--ink) !important;}
/* nav pill = tabs */
.stApp [data-testid="stTabs"] [role="tablist"],.stApp [data-baseweb="tab-list"]{display:flex !important;align-items:center;justify-content:center;gap:6px;width:fit-content !important;max-width:100%;margin:6px auto 26px !important;background:#fff !important;border:0 !important;border-bottom:0 !important;border-radius:999px;padding:9px 9px 9px 26px !important;box-shadow:0 8px 28px rgba(0,0,0,.09);overflow:visible !important;}
.stApp [data-testid="stTabs"] [role="tablist"]::before,.stApp [data-baseweb="tab-list"]::before{content:"Sensite";font-weight:600;font-size:16px;color:#16161a;margin-right:14px;}
.stApp [data-testid="stTabs"] [role="tablist"]::after,.stApp [data-baseweb="tab-list"]::after{content:"Hackshastra 2K26";background:#16161a;color:#fff;font-size:15px;padding:12px 24px;border-radius:999px;margin-left:14px;white-space:nowrap;}
.stApp [data-baseweb="tab-highlight"],.stApp [data-baseweb="tab-border"]{display:none !important;height:0 !important;}
.stApp [data-testid="stTabs"],.stApp [data-testid="stTabs"]>div{border-bottom:0 !important;box-shadow:none !important;}
.stApp button[role="tab"]{border-radius:999px;padding:9px 18px;height:auto;background:transparent !important;border:0 !important;}
.stApp button[role="tab"] p{font-size:15px;color:#555 !important;font-weight:400;}
.stApp button[role="tab"][aria-selected="true"]{background:#f0f0f3 !important;}
.stApp button[role="tab"][aria-selected="true"] p{color:#16161a !important;font-weight:600;}
.stApp [data-testid="stTabs"] [role="tablist"]{flex-wrap:nowrap !important;}
.stApp [data-testid="stTabs"] [role="tablist"]>*:not(button){display:none !important;}
.stApp button[role="tab"],.stApp button[role="tab"][aria-selected="true"]{box-shadow:none !important;border-bottom:0 !important;white-space:nowrap;}
@media (max-width:820px){.stApp [data-testid="stTabs"] [role="tablist"]::before,.stApp [data-testid="stTabs"] [role="tablist"]::after{display:none !important;content:none !important;}
.stApp [data-testid="stTabs"] [role="tablist"]{padding:8px !important;overflow-x:auto !important;justify-content:flex-start !important;}
.stApp button[role="tab"]{padding:8px 12px;} .stApp button[role="tab"] p{font-size:14px;}}
/* widgets forced light */
[data-baseweb="select"]>div,[data-baseweb="textarea"],[data-baseweb="textarea"] textarea,[data-baseweb="base-input"]{background:#fff !important;color:var(--ink) !important;border-radius:16px !important;border-color:#dcdce0 !important;}
[data-baseweb="select"] *{color:var(--ink) !important;}
[data-baseweb="popover"] *,[data-baseweb="menu"],[role="listbox"]{background:#fff !important;color:var(--ink) !important;}
[data-testid="stFileUploaderDropzone"]{background:#fff !important;border-radius:20px;border:1px dashed #c9c9cf;}
[data-testid="stFileUploaderDropzone"] *{color:var(--ink) !important;}
[data-baseweb="tag"]{background:#ffe1d8 !important;border-radius:999px !important;} [data-baseweb="tag"] *{color:#c2300c !important;background:transparent !important;}
[data-testid="stExpander"]{background:#fff;border:0 !important;border-radius:22px;box-shadow:0 6px 20px rgba(0,0,0,.05);margin-bottom:10px;}
[data-testid="stExpander"] *{color:var(--ink) !important;background:transparent;}
.stButton>button,.stDownloadButton>button{border-radius:999px;background:var(--ink) !important;border:0;padding:.6rem 1.5rem;}
.stButton>button *,.stDownloadButton>button *{color:#fff !important;}
.stButton>button:hover,.stDownloadButton>button:hover{background:var(--acc) !important;}
.stApp .stButton button [data-testid="stMarkdownContainer"] p,.stApp .stDownloadButton button [data-testid="stMarkdownContainer"] p,.stApp .stButton button p,.stApp .stDownloadButton button p{color:#fff !important;}
/* components */
.brand{text-align:center;font-weight:600;font-size:20px;margin:4px 0 10px;} .brand i{color:var(--acc);font-style:normal;}
.hero{border-radius:34px;padding:80px 30px 90px;text-align:center;
 background:radial-gradient(60% 90% at 95% 15%,#ff4a1c 0%,rgba(255,74,28,0) 58%),radial-gradient(60% 80% at 5% 95%,#d4d4da 0%,rgba(212,212,218,0) 60%),linear-gradient(135deg,#f7f7f9,#e3e3e8);}
.pill,.tag{display:inline-block;font-size:12px;color:var(--acc) !important;background:#fff;border:1px solid #ffd2c6;border-radius:8px;padding:4px 10px;}
.tag{margin:34px 0 8px;} .hero .pill{margin-bottom:20px;}
.hero h1{font-size:58px;font-weight:400;line-height:1.08;letter-spacing:-1.5px;margin:0 0 16px;}
.hero p{color:#555 !important;font-size:17px;max-width:560px;margin:0 auto;}
h2.sec{font-size:40px;font-weight:400;letter-spacing:-.8px;margin:0 0 18px;line-height:1.15;}
.card{background:#fff;border-radius:28px;padding:26px;box-shadow:0 8px 28px rgba(0,0,0,.06);height:100%;}
.card h4{margin:0 0 10px;font-size:20px;font-weight:500;}
.dark{background:linear-gradient(160deg,#2a2a2f,#0f0f12);border-radius:28px;padding:30px;height:100%;}
.dark,.dark *{color:#fff !important;} .dark .muted{color:#a9a9b3 !important;}
.muted{color:#7d7d86 !important;font-size:14px;}
.big{font-size:70px;font-weight:300;letter-spacing:-2.5px;line-height:1;}
.chip{display:inline-block;font-size:13px;background:#f0f0f3;border-radius:999px;padding:5px 12px;margin:3px 3px 0 0;}
.dark .chip{background:rgba(255,255,255,.12);}
.docview{background:#fff;border-radius:28px;padding:22px 26px;white-space:pre-wrap;word-break:break-word;font-size:15px;line-height:1.9;box-shadow:0 8px 28px rgba(0,0,0,.06);}
.docview mark{border-radius:7px;padding:1px 7px;font-weight:500;}
.docview mark small{font-size:10px;margin-left:5px;opacity:.7;font-weight:400;}
table.t{width:100%;border-collapse:collapse;background:#fff;border-radius:24px;overflow:hidden;box-shadow:0 8px 28px rgba(0,0,0,.06);font-size:14px;}
table.t th{text-align:left;color:#7d7d86;font-weight:400;padding:14px 18px;background:#f7f7f9;} table.t td{padding:12px 18px;border-top:1px solid #efeff2;}
.bar{height:10px;border-radius:99px;background:#ff4a1c;margin:4px 0 12px;}
.foot{text-align:center;color:#7d7d86 !important;font-size:13px;margin:46px 0 10px;}
@media (max-width:700px){.hero h1{font-size:36px}.big{font-size:52px}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

COL = {"Government ID": ("#ffe1d8", "#b92b08"), "Contact": ("#dfe9ff", "#2447b5"), "Financial": ("#d9f2e2", "#17703a"),
       "Credentials": ("#16161a", "#ffffff"), "Personal": ("#f1e1ff", "#7a2fb0"), "Network": ("#e6e6ea", "#444444")}

def highlight(text, findings):
    out, last = [], 0
    for f in findings:
        bg, fg = COL[f.category]
        out += [html.escape(text[last:f.start]),
                f'<mark style="background:{bg};color:{fg}">{html.escape(f.value)}<small>{f.type}</small></mark>']
        last = f.end
    out.append(html.escape(text[last:]))
    return '<div class="docview">' + "".join(out) + "</div>"

def head(tag, title):
    st.markdown(f'<div class="tag">{tag}</div><h2 class="sec">{title}</h2>', unsafe_allow_html=True)

def load_demo(n):
    ss.src, ss.demo_pick = "Demo document", n

t_home, t_an, t_red, t_demo = st.tabs(["Home", "Analyze", "Redact", "Demo data"])

# ---------------- HOME ----------------
with t_home:
    st.markdown("""<div class="hero"><div class="pill">Sensitive information detection</div>
    <h1>Spot sensitive data.<br>Protect it before sharing.</h1>
    <p>Sensite reads your document, highlights Aadhaar, PAN, phone, email, bank and card details, then masks or redacts them in one click.</p></div>""", unsafe_allow_html=True)
    head("How it works", "Three steps, no setup")
    a, b, c = st.columns(3)
    a.markdown('<div class="dark"><div class="big">1</div><h4>Analyze</h4><div class="muted">Paste text, upload a file, or pick a demo document. Sensitive items are found and highlighted instantly.</div></div>', unsafe_allow_html=True)
    b.markdown('<div class="card"><div class="big">2</div><h4>Choose protection</h4><div class="muted">Pick which data types to protect and a style: partial mask, label or black bar.</div></div>', unsafe_allow_html=True)
    c.markdown('<div class="card"><div class="big">3</div><h4>Share safely</h4><div class="muted">Download the protected copy. Nothing is stored; everything stays in your session.</div></div>', unsafe_allow_html=True)
    head("What it detects", "Every common identifier")
    g1, g2 = st.columns(2)
    g1.markdown('<div class="dark"><h4>Personal identifiers</h4><span class="chip">Aadhaar</span><span class="chip">PAN</span><span class="chip">Passport</span><span class="chip">Date of birth</span></div>', unsafe_allow_html=True)
    g2.markdown('<div class="card"><h4>Contact details</h4><span class="chip">Phone number</span><span class="chip">Email</span></div>', unsafe_allow_html=True)
    st.write("")
    g3, g4 = st.columns(2)
    g3.markdown('<div class="card"><h4>Financial data</h4><span class="chip">Credit/debit card</span><span class="chip">Bank account</span><span class="chip">IFSC</span><span class="chip">UPI ID</span></div>', unsafe_allow_html=True)
    g4.markdown('<div class="card"><h4>Credentials and network</h4><span class="chip">Passwords</span><span class="chip">API keys</span><span class="chip">IP address</span></div>', unsafe_allow_html=True)
    head("FAQ", "Common questions")
    with st.expander("Are my documents stored?"):
        st.write("No. Text is processed in memory for your current session only.")
    with st.expander("How are card numbers verified?"):
        st.write("Candidates are checked with the Luhn algorithm, so random long numbers are not flagged as cards.")
    with st.expander("Which files can I upload?"):
        st.write("TXT, CSV, MD, PDF and DOCX.")

# ---------------- ANALYZE ----------------
with t_an:
    head("Analyze", "Find sensitive information")
    st.radio("Source", ["Demo document", "Paste text", "Upload file"], horizontal=True, key="src")
    name, text = "", ""
    if ss.src == "Demo document":
        st.selectbox("Choose a demo document", list(DEMO_DOCS), key="demo_pick")
        name, text = ss.demo_pick, DEMO_DOCS[ss.demo_pick]
    elif ss.src == "Paste text":
        name = "Pasted text"
        text = st.text_area("Paste your text", height=200, placeholder="Paste text with emails, phone numbers, Aadhaar, PAN, card numbers...")
    else:
        up = st.file_uploader("Upload a .txt, .csv, .pdf or .docx file", type=["txt", "csv", "md", "pdf", "docx"])
        if up:
            n = up.name.lower()
            if n.endswith(".pdf"):
                from pypdf import PdfReader
                text = "\n".join(p.extract_text() or "" for p in PdfReader(up).pages)
            elif n.endswith(".docx"):
                from docx import Document
                text = "\n".join(p.text for p in Document(up).paragraphs)
            else:
                text = up.read().decode("utf-8", errors="ignore")
            name = up.name
    ss.doc = (name, text)
    found = scan(text) if text.strip() else []
    if not text.strip():
        st.markdown('<div class="card muted">Add a document above to see highlighted results here.</div>', unsafe_allow_html=True)
    else:
        st.write("")
        cats = {}
        for f in found: cats[f.category] = cats.get(f.category, 0) + 1
        c1, c2 = st.columns([1, 2])
        c1.markdown(f'<div class="dark"><div class="muted">Sensitive items in {html.escape(name)}</div><div class="big">{len(found)}</div><div class="muted">across {len(cats)} categories</div></div>', unsafe_allow_html=True)
        mx = max(cats.values()) if cats else 1
        bars = "".join(f'<div>{k} <span class="muted">({v})</span></div><div class="bar" style="width:{v/mx*100:.0f}%;background:{COL[k][1] if k!="Credentials" else "#16161a"}"></div>' for k, v in cats.items())
        c2.markdown(f'<div class="card"><h4>By category</h4>{bars or "<span class=muted>Nothing detected.</span>"}</div>', unsafe_allow_html=True)
        st.write("")
        st.markdown(highlight(text, found), unsafe_allow_html=True)
        if found:
            st.write("")
            rows = "".join(f'<tr><td>{f.type}</td><td>{f.category}</td><td>{html.escape(f.value)}</td><td>{html.escape(mask_value(f))}</td></tr>' for f in found)
            st.markdown(f'<table class="t"><tr><th>Type</th><th>Category</th><th>Detected</th><th>Masked as</th></tr>{rows}</table>', unsafe_allow_html=True)
            st.caption("Open the Redact tab to protect this document.")
        else:
            st.success("No sensitive information detected. This document looks safe to share.")

# ---------------- REDACT ----------------
with t_red:
    head("Redact", "Protect before sharing")
    name, text = ss.get("doc", ("", ""))
    found = scan(text) if text.strip() else []
    if not found:
        st.markdown('<div class="card muted">Nothing to redact yet. Analyze a document with sensitive data first (try a demo document).</div>', unsafe_allow_html=True)
    else:
        types = sorted({f.type for f in found})
        chosen = st.multiselect("Data types to protect", types, default=types)
        style = st.radio("Protection style", ["Partial mask (keep last 4)", "Label, e.g. [AADHAAR NUMBER]", "Black bars"], horizontal=True)
        mode = {"P": "mask", "L": "label", "B": "block"}[style[0]]
        sel = [f for f in found if f.type in chosen]
        left, right = st.columns(2)
        left.markdown("**Original**")
        left.markdown(highlight(text, sel), unsafe_allow_html=True)
        right.markdown("**Protected copy**")
        red = redact(text, sel, mode)
        right.markdown(f'<div class="docview">{html.escape(red)}</div>', unsafe_allow_html=True)
        st.write("")
        st.markdown(f'<div class="muted">{len(sel)} of {len(found)} items protected in {html.escape(name)}.</div>', unsafe_allow_html=True)
        st.download_button("Download protected copy", red, file_name="protected_document.txt")

# ---------------- DEMO ----------------
with t_demo:
    head("Demo data", "Try a sample document")
    st.markdown('<div class="muted" style="margin-bottom:14px">All data below is synthetic. Load one, then open Analyze.</div>', unsafe_allow_html=True)
    for n, t in DEMO_DOCS.items():
        a, b = st.columns([3, 1])
        a.markdown(f'<div class="card"><h4>{n}</h4><div class="muted" style="white-space:pre-wrap">{html.escape(t[:170])}...</div></div>', unsafe_allow_html=True)
        b.button("Load in Analyze", key="ld" + n, on_click=load_demo, args=(n,))
        if ss.get("demo_pick") == n and ss.src == "Demo document":
            b.markdown('<div class="muted">Loaded. Open the Analyze tab.</div>', unsafe_allow_html=True)
        st.write("")

st.markdown('<div class="foot">Sensite · HackShastra 2K26 · Problem statement CB-02</div>', unsafe_allow_html=True)
