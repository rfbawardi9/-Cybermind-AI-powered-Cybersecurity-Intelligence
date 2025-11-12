# agents_runner.py
from __future__ import annotations
import io
import json
import math
from typing import List, Dict, Any
import pandas as pd

# ---- PDF (ReportLab) ----
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.units import cm

# ------------------------------------------------------------
# Helpers: normalize uploaded content -> list of vulnerability dicts
# Expected fields (case-insensitive, best-effort mapping):
#   CVE, Priority, CVSS, CWE, Description, Effort, Mitigations (semicolon or newline separated)
# ------------------------------------------------------------

def _columns_lower(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df

def _split_mitigations(val: Any) -> List[str]:
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return []
    text = str(val).strip()
    if not text:
        return []
    # Allow either ';' or newline as separators
    parts = []
    for chunk in text.replace('\r', '').split('\n'):
        parts.extend([p.strip() for p in chunk.split(';')])
    return [p for p in parts if p]

def _parse_one_dataframe(df: pd.DataFrame) -> List[Dict[str, Any]]:
    df = _columns_lower(df)
    # Common column aliases
    col_map = {
        "cve": ["cve", "cve_id", "cve id"],
        "priority": ["priority", "severity", "risk"],
        "cvss": ["cvss", "cvss_score", "cvss score"],
        "cwe": ["cwe", "cwe_id"],
        "effort": ["effort", "fix_effort", "remediation effort"],
        "description": ["description", "desc", "summary"],
        "mitigations": ["mitigations", "remediation", "fix", "recommendations"],
    }
    # Resolve columns
    def col(name: str) -> str | None:
        for cand in col_map[name]:
            if cand in df.columns:
                return cand
        return None

    cve_col = col("cve")
    pri_col = col("priority")
    cvss_col = col("cvss")
    cwe_col = col("cwe")
    eff_col = col("effort")
    desc_col = col("description")
    mit_col = col("mitigations")

    items = []
    for _, row in df.iterrows():
        item = {
            "cve": str(row[cve_col]).strip() if cve_col and pd.notna(row.get(cve_col)) else "N/A",
            "priority": str(row[pri_col]).strip() if pri_col and pd.notna(row.get(pri_col)) else "Unknown",
            "cvss": str(row[cvss_col]).strip() if cvss_col and pd.notna(row.get(cvss_col)) else "None",
            "cwe": str(row[cwe_col]).strip() if cwe_col and pd.notna(row.get(cwe_col)) else "N/A",
            "effort": str(row[eff_col]).strip() if eff_col and pd.notna(row.get(eff_col)) else "Medium",
            "description": str(row[desc_col]).strip() if desc_col and pd.notna(row.get(desc_col)) else "",
            "mitigations": _split_mitigations(row.get(mit_col)) if mit_col else [],
        }
        items.append(item)
    return items

def _parse_uploaded_files(uploaded_files: List[Any]) -> List[Dict[str, Any]]:
    """Streamlit UploadedFile list -> normalized items list."""
    all_items: List[Dict[str, Any]] = []
    for f in uploaded_files:
        name = f.name.lower()
        data = f.read()
        # Reset pointer for safety when same file is read again
        f.seek(0)

        try:
            if name.endswith(".csv"):
                df = pd.read_csv(io.BytesIO(data))
                all_items.extend(_parse_one_dataframe(df))
            elif name.endswith(".json"):
                payload = json.loads(data.decode("utf-8", errors="ignore"))
                # Accept either list of dict or dict with "items"
                if isinstance(payload, dict) and "items" in payload:
                    df = pd.DataFrame(payload["items"])
                elif isinstance(payload, list):
                    df = pd.DataFrame(payload)
                else:
                    df = pd.DataFrame([payload])
                all_items.extend(_parse_one_dataframe(df))
            else:
                # Fallback: try CSV first, then JSON
                try:
                    df = pd.read_csv(io.BytesIO(data))
                    all_items.extend(_parse_one_dataframe(df))
                except Exception:
                    payload = json.loads(data.decode("utf-8", errors="ignore"))
                    if isinstance(payload, dict) and "items" in payload:
                        df = pd.DataFrame(payload["items"])
                    elif isinstance(payload, list):
                        df = pd.DataFrame(payload)
                    else:
                        df = pd.DataFrame([payload])
                    all_items.extend(_parse_one_dataframe(df))
        except Exception:
            # Skip unreadable file silently (you could log/raise if preferred)
            continue

    # De-duplicate by CVE if present
    seen = set()
    unique_items = []
    for it in all_items:
        key = (it.get("cve"), it.get("description"))
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(it)
    return unique_items

# ------------------------------------------------------------
# Public API used by app.py
# ------------------------------------------------------------

def run_threat_collector(uploaded_files: List[Any]) -> Dict[str, Any]:
    items = _parse_uploaded_files(uploaded_files)
    return {
        "status": "ok",
        "files_received": [f.name for f in uploaded_files],
        "items": items,
        "summary": f"Collected {len(uploaded_files)} file(s).",
    }

def run_vuln_analysis(threat_data: Dict[str, Any]) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = threat_data.get("items", [])
    # Basic counts
    levels = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for it in items:
        sev = str(it.get("priority", "unknown")).lower()
        if sev not in levels:
            sev = "unknown"
        levels[sev] += 1
    return {
        "status": "ok",
        "items": items,
        "counts": levels,
        "vuln_summary": f"Found {len(items)} vulns "
                        f"({levels['critical']} critical, {levels['high']} high, {levels['medium']} medium)."
    }

def run_mitigation_strategist(vuln_results: Dict[str, Any]) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = vuln_results.get("items", [])
    actions = []
    for it in items:
        actions.extend(it.get("mitigations", []))
    # De-duplicate while keeping order
    seen = set()
    unique = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            unique.append(a)
    return {"status": "ok", "actions": unique}

# ------------------------------------------------------------
# PDF generator 
# ------------------------------------------------------------

def _styles():
    ss = getSampleStyleSheet()
    title = ParagraphStyle(
        "TitleBig",
        parent=ss["Title"],
        fontSize=22,
        leading=26,
        spaceAfter=12,
    )
    subtitle = ParagraphStyle(
        "SubTitle",
        parent=ss["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.grey,
        spaceAfter=16,
    )
    h2 = ParagraphStyle(
        "Heading2Black",
        parent=ss["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=16,
        spaceAfter=8,
    )
    normal = ss["BodyText"]
    bold = ParagraphStyle("Bold", parent=normal, fontName="Helvetica-Bold")
    return title, subtitle, h2, normal, bold

def _summary_table(items: List[Dict[str, Any]]) -> Table:
    data = [["CVE", "Priority", "CVSS", "Key Mitigations"]]
    for it in items:
        key_mit = " • ".join(it.get("mitigations", [])[:1])  # first mitigation line in the table
        data.append([
            it.get("cve", "N/A"),
            it.get("priority", "Unknown"),
            it.get("cvss", "None"),
            key_mit or "—",
        ])
    tbl = Table(
        data,
        colWidths=[4*cm, 3*cm, 2.5*cm, 8*cm],
        hAlign="LEFT",
        repeatRows=1
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2F2F2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (1, 1), (2, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl

def _detailed_findings(items: List[Dict[str, Any]], styles) -> List[Any]:
    title, subtitle, h2, normal, bold = styles
    flow = [Paragraph("Detailed Findings", h2), Spacer(1, 6)]
    for idx, it in enumerate(items, start=1):
        flow.append(
            Paragraph(f"<b>{idx}. {it.get('cve','N/A')}</b>", normal)
        )
        flow.append(
            Paragraph(
                f"<b>Priority:</b> {it.get('priority','Unknown')}  &nbsp;&nbsp;"
                f"<b>Effort:</b> {it.get('effort','Medium')}  &nbsp;&nbsp;"
                f"<b>CVSS:</b> {it.get('cvss','None')}  &nbsp;&nbsp;"
                f"<b>CWE:</b> {it.get('cwe','N/A')}",
                normal
            )
        )
        if it.get("description"):
            flow.append(Paragraph(f"<b>Description:</b> {it['description']}", normal))

        # Recommended mitigations as a numbered list
        mitigs = it.get("mitigations", [])
        if mitigs:
            flow.append(Paragraph("<b>Recommended Mitigations:</b>", normal))
            for n, m in enumerate(mitigs, start=1):
                flow.append(Paragraph(f"{n}  {m}", normal))
        else:
            flow.append(Paragraph("<b>Recommended Mitigations:</b> —", normal))

        # References
        flow.append(Paragraph("<b>References:</b>", normal))
        flow.append(Paragraph(f"• {it.get('cve','N/A')}", normal))
        flow.append(Spacer(1, 10))
    return flow

def generate_report(
    threat_data: Dict[str, Any],
    vuln_results: Dict[str, Any],
    mitigation_plan: Dict[str, Any],
    output_pdf_path: str
) -> str:
    """Create the final PDF matching the desired layout."""
    items: List[Dict[str, Any]] = threat_data.get("items", [])

    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=A4,
        leftMargin=2*cm,
        rightMargin=2*cm,
        topMargin=1.6*cm,
        bottomMargin=1.6*cm,
    )
    styles = _styles()
    title, subtitle, h2, normal, bold = styles

    story: List[Any] = []
    # Title + subtitle
    story.append(Paragraph("CyberMind — Security Report", title))
    sub = ("This table provides a summary of the most recent cyber threats identified "
           "by the CyberMind system, including their severity levels, CVSS scores, and "
           "key recommended mitigations.")
    story.append(Paragraph(sub, subtitle))
    story.append(Spacer(1, 10))

    # Summary table
    story.append(_summary_table(items))
    story.append(Spacer(1, 16))
    story.append(PageBreak())

    # Detailed Findings
    story.extend(_detailed_findings(items, styles))

    doc.build(story)
    return output_pdf_path
