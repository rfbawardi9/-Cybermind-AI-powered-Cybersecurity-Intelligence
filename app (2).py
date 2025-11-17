# app.py — CyberMind Streamlit Dashboard (JSON / CSV / PDF / Custom GPT)

import io, json, re
from datetime import datetime

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# ───────── Page setup ─────────
st.set_page_config(page_title="CyberMind Dashboard", page_icon="🛡", layout="wide")
PRIMARY = "#0B5ED7"; ACCENT = "#22B07D"; MUTED = "#6c757d"
st.markdown(f"""
<style>
.cm-badge {{display:inline-block;padding:4px 10px;border-radius:999px;background:{ACCENT}15;color:{ACCENT};
            font-weight:600;font-size:12px;border:1px solid {ACCENT}55;}}
.cm-card {{border:1px solid #e9ecef;padding:16px;border-radius:12px;background:white;}}
.cm-h1 {{font-size:28px;font-weight:800;color:{PRIMARY};margin-bottom:0}}
.cm-sub {{color:{MUTED};font-size:13px}}
</style>
""", unsafe_allow_html=True)

# ───────── Demo data (for when no file is uploaded) ─────────
DEMO_DATA = [
    {
        "cve_id": "CVE-2025-59248",
        "title": "Microsoft Exchange Server – spoofing & auth issues",
        "description": "Multiple high-severity issues in Exchange may enable spoofing and privilege escalation.",
        "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
        "priority": "Critical",
        "effort": "Medium",
        "mitigations": [
            "Apply latest Microsoft security updates.",
            "Enforce strong authentication & input validation.",
            "Audit logs for suspicious auth flows."
        ],
        "references": ["https://msrc.microsoft.com/update-guide/"],
        "source": "Demo"
    },
    {
        "cve_id": "CVE-2025-53782",
        "title": "SQL Injection in Product X",
        "description": "Insufficient sanitization allows SQL injection in login workflow.",
        "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "priority": "High",
        "effort": "Medium",
        "mitigations": [
            "Use parameterized queries / prepared statements.",
            "Centralize input validation.",
            "WAF rules for SQLi signatures."
        ],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        "source": "Demo"
    },
    {
        "cve_id": "CVE-2025-55999",
        "title": "Outdated 3rd-party library in backend",
        "description": "Known vulnerable dependency may lead to RCE under certain configs.",
        "cvss_v3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "priority": "Medium",
        "effort": "Low",
        "mitigations": [
            "Upgrade dependency to a patched version.",
            "Pin versions and enable Dependabot.",
            "SBOM + regular SCA scans."
        ],
        "references": ["https://nvd.nist.gov/"],
        "source": "Demo"
    },
]

# ───────── Helpers ─────────

def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def _try_float(x):
    try:
        return float(x)
    except Exception:
        return None

def extract_cvss_score(it: dict):
    # direct numeric
    for k in ["cvss_score", "cvssScore", "baseScore"]:
        if k in it:
            s = _try_float(it[k])
            if s is not None:
                return s
    # vector-like strings
    for k in ["cvss_v3", "cvss", "cvssVector"]:
        v = it.get(k)
        if isinstance(v, str):
            m = re.search(r"(\d+\.\d+)", v)
            if m:
                return _try_float(m.group(1))
    # severity arrays
    sev = it.get("severity")
    if isinstance(sev, list):
        for s in sev:
            if isinstance(s, dict):
                for kk in ["score", "baseScore", "value"]:
                    sc = _try_float(s.get(kk))
                    if sc is not None:
                        return sc
                txt = " ".join([str(x) for x in s.values() if isinstance(x, str)])
                m = re.search(r"(\d+\.\d+)", txt)
                if m:
                    return _try_float(m.group(1))
    # NVD metrics trees
    metrics = it.get("metrics") or {}
    if isinstance(metrics, dict):
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            arr = metrics.get(key)
            if isinstance(arr, list) and arr:
                data = arr[0].get("cvssData") if isinstance(arr[0], dict) else None
                if isinstance(data, dict) and "baseScore" in data:
                    sc = _try_float(data["baseScore"])
                    if sc is not None:
                        return sc
    # fallback: scan any string
    for v in it.values():
        if isinstance(v, str):
            m = re.search(r"(\d+\.\d+)", v)
            if m:
                return _try_float(m.group(1))
    return None

def priority_from_cvss(score):
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"

# Rules to detect some common vulnerability types
MITIGATION_RULES = [
    (r"sql\s*injection|sqli", [
        "Use parameterized queries / prepared statements.",
        "Centralize input validation & encoding.",
        "Enable WAF rules for SQLi signatures."
    ]),
    (r"\bxss\b|cross[-\s]?site", [
        "Encode untrusted data in HTML/JS contexts.",
        "Use Content-Security-Policy (CSP).",
        "Sanitize and validate all inputs."
    ]),
    (r"\brce\b|remote code", [
        "Patch vulnerable components immediately.",
        "Run services with least privilege.",
        "Restrict egress and monitor exec calls."
    ]),
    (r"authentica|authorization|privilege", [
        "Enforce MFA and strong authentication.",
        "Harden session management and token TTL.",
        "Apply least-privilege on roles."
    ]),
]

# Fallback generic mitigations → used when we don't recognize the vuln type
DEFAULT_MITIGATIONS = [
    "Apply latest security patches and vendor updates.",
    "Restrict access using least-privilege accounts.",
    "Enable detailed logging and monitor for suspicious activity."
]

def suggest_mitigations(text: str):
    text = (text or "").lower()
    out = []
    for pat, tips in MITIGATION_RULES:
        if re.search(pat, text):
            out.extend(tips)
    # unique + cap length
    return list(dict.fromkeys(out))[:6]

def normalize_records(raw):
    """Normalize list[dict] to DataFrame with unified columns, and ALWAYS set mitigations."""
    rows = []
    for it in raw:
        try:
            cve_id = it.get("cve_id") or it.get("id") or it.get("CVE") or it.get("cveId") or ""
            title  = it.get("title") or it.get("summary") or it.get("name") or ""
            desc   = it.get("description") or it.get("details") or it.get("desc") or ""

            # NVD CVE 5.x (containers.cna)
            if not (title or desc):
                cna = (it.get("containers") or {}).get("cna") or {}
                if not title:
                    title = cna.get("title") or ""
                if not desc:
                    for d in ensure_list(cna.get("descriptions")):
                        if isinstance(d, dict) and d.get("lang") == "en":
                            desc = d.get("value") or desc

            cvss_vec = it.get("cvss_v3") or it.get("cvss") or ""
            cvss_num = extract_cvss_score(it)

            prio = (it.get("priority") or "").title()
            if not prio or prio == "Unknown":
                prio = priority_from_cvss(cvss_num)

            # 1) start with any existing mitigations from source
            mit = ensure_list(it.get("mitigations") or it.get("MitigationSteps"))

            # 2) if still empty → try rules
            if not mit:
                mit = suggest_mitigations(f"{title} {desc}")

            # 3) if still empty → apply generic fallback
            if not mit:
                mit = DEFAULT_MITIGATIONS.copy()

            refs = ensure_list(it.get("references"))

            effort = (it.get("effort") or "Unknown").title()
            source = it.get("source") or "Uploaded"

            rows.append({
                "cve_id": cve_id,
                "title": title,
                "description": desc,
                "cvss_v3": cvss_vec,
                "priority": prio,
                "effort": effort,
                "mitigations": ", ".join(mit) if mit else "",
                "references": ", ".join(refs) if refs else "",
                "source": source,
                "cvss_numeric": cvss_num
            })
        except Exception:
            continue

    df = pd.DataFrame(rows)
    if len(df) == 0:
        return pd.DataFrame(columns=[
            "cve_id","title","description","cvss_v3","priority",
            "effort","mitigations","references","source","cvss_numeric"
        ])
    return df

def load_any_file(uploaded):
    """Load JSON/CSV exported from your 4 agents or from NVD/scanner."""
    name = uploaded.name.lower()
    if name.endswith(".json"):
        data = json.load(uploaded)
        # many exports use {"items":[...]} or {"vulnerabilities":[...]}
        if isinstance(data, dict):
            for key in ["items", "vulnerabilities", "vulns", "results"]:
                if key in data and isinstance(data[key], list):
                    return data[key]
            # single object → wrap in list
            return [data]
        return data
    elif name.endswith(".csv"):
        df = pd.read_csv(uploaded)
        return df.to_dict(orient="records")
    else:
        st.warning("Please upload JSON or CSV.")
        return []

def kpi_card(label, value, help_txt=None):
    st.markdown(
        f"""
        <div class="cm-card">
          <div class="cm-sub">{label}</div>
          <div style="font-size:26px;font-weight:800;margin-top:2px">{value}</div>
          {f'<div class="cm-sub" style="margin-top:4px">{help_txt}</div>' if help_txt else ''}
        </div>
        """,
        unsafe_allow_html=True
    )

def filter_dataframe(df, query, severities):
    out = df.copy()
    if query:
        q = query.lower().strip()
        mask = (
            out["cve_id"].str.lower().str.contains(q, na=False) |
            out["title"].str.lower().str.contains(q, na=False) |
            out["description"].str.lower().str.contains(q, na=False)
        )
        out = out[mask]
    if severities and "All" not in severities:
        out = out[out["priority"].isin(severities)]
    return out

# ───────── PDF generation (all rows, wrapped text) ─────────
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, ListFlowable, ListItem
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch

def make_pdf(df_in, filter_prio=None):
    """Generate in-memory PDF using reportlab (wrapped + NVD-safe)."""

    df = df_in.copy()
    if filter_prio and filter_prio != "All":
        df = df[df["priority"] == filter_prio]

    if df.empty:
        st.error(f"No records found for priority: {filter_prio}")
        return None, None

    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    Title = styles["Title"]; Title.fontSize = 22
    H2 = styles["Heading2"]; H2.fontSize = 14
    Normal = styles["Normal"]

    Wrapped = ParagraphStyle(
        "Wrapped",
        parent=Normal,
        fontSize=9,
        leading=11,
        wordWrap="CJK",
    )

    TableWrapped = ParagraphStyle(
        "TableWrapped",
        parent=Normal,
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    )

    story = []

    report_title = f"CyberMind — Consolidated Security Report ({filter_prio or 'All'} Findings)"
    story.append(Paragraph(report_title, Title))
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated: {ts}", Normal))
    story.append(Spacer(1, 12))

    total = len(df)
    critical = int((df["priority"] == "Critical").sum()) if "priority" in df else 0

    story.append(Paragraph("Executive Summary", H2))
    story.append(Paragraph(
        f"Total findings in report: <b>{total}</b> &nbsp;&nbsp;|&nbsp;&nbsp; Critical: <b>{critical}</b>",
        Normal,
    ))
    story.append(Spacer(1, 10))

    # TABLE header
    rows = [[
        Paragraph("CVE", Normal),
        Paragraph("Priority", Normal),
        Paragraph("CVSS", Normal),
        Paragraph("Key Mitigations", Normal),
    ]]

    # include **all** rows (no 15-limit)
    for _, r in df.iterrows():
        cvss = r.get("cvss_v3", "—")
        mit_raw = r.get("mitigations", "") or ""
        if mit_raw.lower() in ["none", "nan"] or not mit_raw:
            mit_raw = "—"
        # keep up to ~300 chars so the table stays readable
        mit_text = mit_raw[:300]

        rows.append([
            Paragraph(r.get("cve_id", "—"), TableWrapped),
            Paragraph(r.get("priority", "Unknown"), TableWrapped),
            Paragraph(cvss, TableWrapped),
            Paragraph(mit_text, TableWrapped),
        ])

    tbl = Table(
        rows,
        repeatRows=1,
        colWidths=[1.3 * inch, 0.9 * inch, 1.0 * inch, 3.3 * inch],
        hAlign="LEFT",
    )

    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0F0F0")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, 0), 1, colors.black),
    ]))

    story.append(tbl)
    story.append(Spacer(1, 14))
    story.append(PageBreak())

    # Detailed Findings
    story.append(Paragraph("Detailed Findings", H2))
    story.append(Spacer(1, 8))

    for i, (_, r) in enumerate(df.iterrows(), start=1):
        story.append(Paragraph(f"{i}. {r.get('cve_id', 'UNKNOWN')}", styles["Heading3"]))

        story.append(Paragraph(f"<b>Title:</b> {r.get('title', '—')}", Wrapped))
        story.append(Paragraph(
            f"<b>Priority:</b> {r.get('priority', 'Unknown')} &nbsp;&nbsp; "
            f"<b>Effort:</b> {r.get('effort', 'Unknown')} &nbsp;&nbsp; "
            f"<b>CVSS:</b> {r.get('cvss_v3', '—')}",
            Wrapped,
        ))

        desc = r.get("description", "—") or "—"
        story.append(Paragraph(f"<b>Description:</b><br/>{desc}", Wrapped))

        mit_raw = r.get("mitigations", "") or ""
        mit_list = (
            [x.strip() for x in mit_raw.split(",") if x.strip()]
            if mit_raw.lower() not in ["none", "nan"] and mit_raw
            else []
        )

        if mit_list:
            story.append(Paragraph("<b>Mitigations:</b>", Normal))
            story.append(ListFlowable(
                [ListItem(Paragraph(x, Wrapped)) for x in mit_list[:8]],
                bulletType="bullet",
                start="circle",
            ))

        ref_raw = r.get("references", "") or ""
        ref_list = [x.strip() for x in ref_raw.split(",") if x.strip()]
        if ref_list:
            story.append(Paragraph("<b>References:</b>", Normal))
            story.append(ListFlowable(
                [ListItem(Paragraph(x, Wrapped)) for x in ref_list[:8]],
                bulletType="bullet",
            ))

        story.append(Spacer(1, 12))

    doc.build(story)
    buf.seek(0)

    prio_suffix = f"_{filter_prio}" if filter_prio and filter_prio != "All" else ""
    filename = f"CyberMind_Report{prio_suffix}_{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.pdf"
    return buf, filename

# ───────── Simple lexical QA (fallback) ─────────
def detect_priority_from_question(q: str):
    q = q.lower()
    if "critical" in q:
        return "Critical"
    if "high" in q:
        return "High"
    if "medium" in q or "meduim" in q:
        return "Medium"
    if "low" in q:
        return "Low"
    return None

def simple_qa(df, question):
    """Tiny lexical Q&A over the loaded data."""
    q = question.lower().strip()
    if not len(df):
        return "No data loaded yet."
    scored = []
    for _, r in df.iterrows():
        text = f"{r.get('title','')} {r.get('description','')}".lower()
        score = sum(1 for token in q.split() if token in text)
        if score > 0:
            scored.append((score, r))
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [r for _, r in scored[:3]] if scored else []
    lines = ["Here’s what I found:"]
    for r in top:
        lines.append(
            f"- {r.get('cve_id','?')} — {r.get('priority','Unknown')}: "
            f"{(r.get('title') or r.get('description',''))[:80]}..."
        )
    if not top:
        lines.append("- No exact matches. Try another keyword.")
    return "\n".join(lines)

# ───────── OpenAI enrichment & Ask-CyberMind GPT ─────────
OPENAI_MODEL = "gpt-4o-mini"

def _get_openai_client():
    """
    Try to read OPENAI_API_KEY from:
    1) st.secrets["OPENAI_API_KEY"]
    2) os.environ["OPENAI_API_KEY"]
    and show clear errors in the sidebar.
    """
    import os
    from openai import OpenAI

    key = None
    source = None

    # 1) جرّبي secrets أول
    try:
        key = st.secrets["OPENAI_API_KEY"]
        source = "Streamlit secrets"
    except Exception:
        key = None

    # 2) لو ما لقي شيء في secrets → خذ من environment
    if not key:
        key = os.getenv("OPENAI_API_KEY")
        if key:
            source = "environment variable"

    # 3) لو لسا فاضي → رجّع خطأ واضح في الـ sidebar
    if not key:
        st.sidebar.error(
            "No OPENAI_API_KEY found.\n\n"
            "Either add it to `.streamlit/secrets.toml` as:\n"
            'OPENAI_API_KEY=\"sk-...\"\n'
            "or set it in Python using:\n"
            'os.environ[\"OPENAI_API_KEY\"] = \"sk-...\"'
        )
        return None

    # 4) جرّب إنشاء الـ client
    try:
        client = OpenAI(api_key=key)
        st.sidebar.success(f"CyberMind GPT connected via {source}.")
        return client
    except Exception as e:
        st.sidebar.error(f"Failed to initialize OpenAI client:\n{e}")
        return None

AI_SYSTEM_ENRICH = (
    "You are a cybersecurity assistant. Given a vulnerability text, "
    "return a SHORT, ACTIONABLE, JSON object with keys: "
    "priority (Critical/High/Medium/Low/Unknown), "
    "category (SQL Injection, XSS, RCE, Auth, Misconfiguration, DoS, InfoLeak, Other), "
    "summary, mitigations (array), estimated_effort (Low/Medium/High), references (array)."
)

def _ai_classify(client, title: str, desc: str) -> dict:
    if not client:
        return {}
    prompt = (
        "TEXT:\n\"\"\"\n" + (title or "") + "\n" + (desc or "") + "\n\"\"\"\n\n"
        "Return ONLY valid JSON with keys: priority, category, summary, mitigations, "
        "estimated_effort, references."
    )
    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.2,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": AI_SYSTEM_ENRICH},
                {"role": "user", "content": prompt},
            ],
        )
        return json.loads(resp.choices[0].message.content)
    except Exception:
        return {}

def enrich_df_with_ai(df: pd.DataFrame, batch_size: int = 200) -> pd.DataFrame:
    """
    Use OpenAI to fill missing priority/description/mitigations for ALL severities.
    (Critical / High / Medium / Low)
    """
    client = _get_openai_client()
    if client is None or df.empty:
        return df

    needs_ai_enrichment = (
        df["priority"].fillna("").eq("Unknown") |
        df["mitigations"].fillna("").eq("") |
        df["description"].fillna("").eq("")
    )

    idxs = df[needs_ai_enrichment].head(batch_size).index.tolist()
    if not idxs:
        return df

    st.info(f"AI enriching {len(idxs)} records (all severities)…")

    for rid in idxs:
        r = df.loc[rid].to_dict()
        ai = _ai_classify(client, r.get("title", ""), r.get("description", ""))

        if isinstance(ai, dict) and ai:
            # priority
            if r.get("priority") in (None, "", "Unknown"):
                df.at[rid, "priority"] = ai.get("priority", "Unknown")

            # description
            if not r.get("description"):
                df.at[rid, "description"] = ai.get("summary", "")

            # mitigations: merge existing + AI
            mits_ai = ai.get("mitigations") or []
            base_mits = [x.strip() for x in str(r.get("mitigations", "")).split(",") if x.strip()]

            if mits_ai:
                merged = list(dict.fromkeys(
                    base_mits + [str(x).strip() for x in mits_ai if str(x).strip()]
                ))
                df.at[rid, "mitigations"] = ", ".join(merged)

            # effort
            if r.get("effort") in (None, "", "Unknown"):
                df.at[rid, "effort"] = (ai.get("estimated_effort", "Unknown") or "Unknown").title()

            # references
            refs_ai = ai.get("references") or []
            if refs_ai:
                base = [x.strip() for x in str(r.get("references", "")).split(",") if x.strip()]
                merged_r = list(dict.fromkeys(
                    base + [str(x).strip() for x in refs_ai if str(x).strip()]
                ))
                df.at[rid, "references"] = ", ".join(merged_r)

    return df

# Custom GPT that answers questions based on the loaded dataframe
AI_SYSTEM_QA = (
    "You are CyberMind GPT, a cybersecurity analyst. "
    "You will receive a list of vulnerabilities as JSON lines plus a user question. "
    "Answer ONLY based on that data. "
    "Be concise but clear, and reference CVE IDs when useful."
)

def ask_cybermind_gpt(df: pd.DataFrame, question: str) -> str:
    """
    Custom GPT: uses df (all vulnerabilities) as 'memory', and OpenAI for reasoning.
    Falls back to simple_qa if anything fails.
    """
    client = _get_openai_client()
    if client is None:
        return "CyberMind GPT is temporarily unavailable, falling back to basic search.\n\n" + simple_qa(df, question)

    if df.empty:
        return "No data loaded yet."

    # pick top relevant rows using the same keyword scoring as simple_qa
    q = question.lower().strip()
    scored = []
    for _, r in df.iterrows():
        text = f"{r.get('title','')} {r.get('description','')}".lower()
        score = sum(1 for token in q.split() if token in text)
        if score > 0:
            scored.append((score, r))
    scored.sort(key=lambda x: x[0], reverse=True)
    top_rows = [r for _, r in scored[:12]] if scored else df.head(12).to_dict(orient="records")

    # build JSON lines context
    context_lines = []
    for r in top_rows:
        if not isinstance(r, dict):
            r = r.to_dict()
        mini = {
            "cve_id": r.get("cve_id"),
            "title": r.get("title"),
            "priority": r.get("priority"),
            "cvss": r.get("cvss_v3"),
            "mitigations": r.get("mitigations"),
            "description": (r.get("description") or "")[:400],
        }
        context_lines.append(json.dumps(mini))

    context_str = "\n".join(context_lines)
    user_prompt = (
        "VULNERABILITIES (one JSON per line):\n"
        f"{context_str}\n\n"
        f"QUESTION:\n{question}\n\n"
        "Answer using the vulnerabilities above only. "
        "If the user asks for 'high vulnerabilities', list them. "
        "If they ask 'explain mitigations', explain the steps in simple terms."
    )

    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.2,
            messages=[
                {"role": "system", "content": AI_SYSTEM_QA},
                {"role": "user", "content": user_prompt},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return "CyberMind GPT is temporarily unavailable, falling back to basic search.\n\n" + simple_qa(df, question)

# ───────── Sidebar (input & filters) ─────────
st.sidebar.title("🛠 Controls")
uploaded = st.sidebar.file_uploader(
    "Upload CyberMind data (JSON / CSV)",
    type=["json", "csv"]
)
st.sidebar.markdown(
    '<span class="cm-sub">If empty, demo data will be used.</span>',
    unsafe_allow_html=True
)

raw = load_any_file(uploaded) if uploaded else DEMO_DATA
df = normalize_records(raw)

# AI enrichment only when user uploads file
if len(df) and uploaded is not None:
    with st.spinner("AI enrichment in progress (auto)…"):
        df = enrich_df_with_ai(df, batch_size=200)
    st.sidebar.success("AI enrichment complete!")

st.sidebar.divider()
query = st.sidebar.text_input("Search in CVE / title / description", "")
severities = st.sidebar.multiselect(
    "Filter by Priority",
    ["All", "Critical", "High", "Medium", "Low", "Unknown"],
    default=["All"]
)

def apply_filters(df, query, severities):
    return filter_dataframe(df, query, severities or ["All"])

filtered = apply_filters(df, query, severities)

st.sidebar.divider()
st.sidebar.subheader("💬 Ask CyberMind")
user_q = st.sidebar.text_input("Ask (e.g., 'Explain mitigations for medium vulns')", "")

if user_q:
    answer = ask_cybermind_gpt(filtered, user_q)
    st.sidebar.markdown(answer)

# ───────── Header ─────────
colA, colB = st.columns([0.7, 0.3])
with colA:
    st.markdown('<div class="cm-h1">CyberMind Dashboard</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="cm-sub">AI-Powered Multi-Agent Cybersecurity Intelligence Framework</div>',
        unsafe_allow_html=True
    )
with colB:
    st.markdown(f'<span class="cm-badge">Live Prototype</span>', unsafe_allow_html=True)
    st.caption(f"Records loaded: {len(df)}  |  Filtered: {len(filtered)}")
st.divider()

# ───────── KPIs ─────────
c1, c2, c3, c4, c5 = st.columns(5)
with c1: kpi_card("Total Findings", len(filtered))
with c2: kpi_card("Critical Priority", int((filtered["priority"] == "Critical").sum()) if "priority" in filtered else 0)
with c3: kpi_card("High Priority", int((filtered["priority"] == "High").sum()) if "priority" in filtered else 0)
with c4: kpi_card("With Mitigations", int(filtered["mitigations"].astype(bool).sum()))
with c5: kpi_card("Unique Sources", filtered["source"].nunique() if "source" in filtered else 1)

st.divider()

# ───────── Tabs ─────────
t1, t2, t3, t4, t5 = st.tabs(["Overview", "Threats", "Vulnerabilities", "Mitigations", "Report"])

with t1:
    st.subheader("Overview")
    if len(filtered):
        dist = filtered["priority"].fillna("Unknown").value_counts()
        fig, ax = plt.subplots()
        dist.plot(kind="bar", ax=ax)
        ax.set_title("Priority Distribution")
        ax.set_xlabel("Priority")
        ax.set_ylabel("Count")
        st.pyplot(fig)
    st.dataframe(
        filtered[["cve_id", "title", "priority", "cvss_v3", "source"]],
        use_container_width=True,
        height=360
    )

with t2:
    st.subheader("Threats (Raw)")
    st.dataframe(
        filtered[["cve_id", "title", "description", "source"]],
        use_container_width=True,
        height=480
    )

with t3:
    st.subheader("Vulnerabilities")
    left, right = st.columns([0.55, 0.45])
    with left:
        st.markdown("Top items by CVSS (approx)")
        st.dataframe(
            filtered.sort_values("cvss_numeric", ascending=False)[["cve_id", "title", "cvss_v3", "priority"]].head(15),
            use_container_width=True,
            height=380
        )
    with right:
        st.markdown("CVSS (approx) Histogram")
        if filtered["cvss_numeric"].notna().any():
            fig2, ax2 = plt.subplots()
            filtered["cvss_numeric"].dropna().plot(kind="hist", bins=8, ax=ax2)
            ax2.set_xlabel("CVSS (approx)")
            st.pyplot(fig2)
        else:
            st.info("No numeric CVSS parsed from the dataset.")

with t4:
    st.subheader("Mitigations")
    st.dataframe(
        filtered[filtered["mitigations"].astype(bool)][["cve_id", "priority", "mitigations", "references"]],
        use_container_width=True,
        height=480
    )

with t5:
    st.subheader("Generate Report")

    report_priority = st.selectbox(
        "Filter Report by Priority:",
        options=["All", "Critical", "High", "Medium", "Low", "Unknown"],
        index=0,
        key="pdf_prio_filter"
    )

    col_pdf, col_json, col_csv = st.columns(3)

    with col_pdf:
        if st.button(f" Generate PDF ({report_priority} Only)", key="pdf_gen"):
            pdf_bytes, fname = make_pdf(df, filter_prio=report_priority)

            if pdf_bytes is None:
                st.error("Could not generate PDF. Check filters or data.")
            else:
                st.success("PDF generated successfully!")

                st.download_button(
                    label=" Download PDF",
                    data=pdf_bytes,
                    file_name=fname,
                    mime="application/pdf",
                    key="pdf_dl",
                )

                import os
                save_folder = "saved_reports"
                os.makedirs(save_folder, exist_ok=True)
                local_path = os.path.join(save_folder, fname)

                with open(local_path, "wb") as f:
                    f.write(pdf_bytes.getbuffer())

                st.info(f"PDF also saved on server at: {local_path}")

    with col_json:
        st.write("Download JSON (all records)")
        json_data = df.to_json(orient="records", indent=2)
        st.download_button(
            label=" Download JSON",
            data=json_data,
            file_name="cybermind_findings.json",
            mime="application/json",
            key="json_dl",
        )

    with col_csv:
        st.write("Download CSV (all records)")
        csv_data = df.to_csv(index=False)
        st.download_button(
            label=" Download CSV",
            data=csv_data,
            file_name="cybermind_findings.csv",
            mime="text/csv",
            key="csv_dl",
        )

st.caption("© CyberMind — SDA Generative AI / LLM Bootcamp")
