# agents_runner.py
import json
import csv
import io
from typing import List, Dict, Any

def _read_uploaded_file(uploaded_file) -> Any:
    """
    uploaded_file is a Streamlit UploadedFile (has .read())
    Try parse as JSON, then CSV, else return text.
    """
    b = uploaded_file.read()
    # rewind not necessary because Streamlit UploadedFile gives bytes
    # try JSON
    try:
        return json.loads(b.decode('utf-8'))
    except Exception:
        pass

    # try CSV
    try:
        text = b.decode('utf-8')
        reader = csv.DictReader(io.StringIO(text))
        rows = [r for r in reader]
        if rows:
            return {"csv_rows": rows}
    except Exception:
        pass

    # fallback plain text
    try:
        return {"text": b.decode('utf-8', errors='ignore')}
    except Exception:
        return {"raw_bytes_len": len(b)}


def run_threat_collector(uploaded_files) -> Dict:
    """
    Read uploaded_files (list of Streamlit UploadedFile) and extract
    a simple summary structure to pass downstream.
    """
    if not uploaded_files:
        return {"status": "error", "message": "No files provided."}

    parsed_files = []
    for uf in uploaded_files:
        parsed = _read_uploaded_file(uf)
        parsed_files.append({"filename": uf.name, "content": parsed})

    # a simple summary
    summary = {
        "status": "ok",
        "files_received": [p["filename"] for p in parsed_files],
        "parsed_files": parsed_files,
        "summary": f"Collected {len(parsed_files)} file(s)."
    }
    return summary


def run_vuln_analysis(threat_data: Dict) -> Dict:
    """
    Given the threat_data (from run_threat_collector), find vulnerabilities.
    This example looks for a key "vulnerabilities" inside parsed JSON if exists,
    or tries to derive counts from CSV rows.
    """
    vulns = []
    for pf in threat_data.get("parsed_files", []):
        content = pf["content"]
        if isinstance(content, dict) and "vulnerabilities" in content:
            # assume a list of vulnerability dicts
            for v in content["vulnerabilities"]:
                vulns.append(v)
        elif isinstance(content, dict) and "csv_rows" in content:
            # try to map CSV rows with 'id' and 'severity'
            for row in content["csv_rows"]:
                vulns.append({
                    "id": row.get("id") or row.get("cve") or "unknown",
                    "severity": row.get("severity") or row.get("level") or "unknown",
                    "description": row.get("description") or ""
                })
        # else skip plain text in this simple example

    # build a summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in vulns:
        sev = (v.get("severity") or "unknown").lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] += 1

    return {
        "status": "ok",
        "vulnerabilities": vulns,
        "vuln_summary": f"Found {len(vulns)} vulns ({counts['critical']} critical, {counts['high']} high, {counts['medium']} medium).",
        "counts": counts
    }


def run_mitigation_strategist(vuln_results: Dict) -> Dict:
    """
    Create simple mitigation actions based on severity counts.
    """
    counts = vuln_results.get("counts", {})
    actions = []
    if counts.get("critical", 0) > 0:
        actions.append("Patch critical CVEs within 24 hours")
    if counts.get("high", 0) > 0:
        actions.append("Prioritize high-severity remediation in next sprint")
    if counts.get("unknown", 0) > 0:
        actions.append("Investigate unknown severity findings")

    return {"status": "ok", "actions": actions}


def generate_report(threat_data: Dict, vuln_results: Dict, mitigation_plan: Dict, output_pdf_path: str) -> str:
    """
    Simple PDF generator: write plain text into a PDF using reportlab (must be in requirements).
    Returns the path to created PDF.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(output_pdf_path, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Sybermind Report (AUTO)")
    y -= 30

    c.setFont("Helvetica", 10)
    c.drawString(40, y, "=== Threat Data ===")
    y -= 16
    c.drawString(40, y, str(threat_data.get("summary", "")))
    y -= 16
    c.drawString(40, y, json.dumps({"files_received": threat_data.get("files_received")}))
    y -= 30

    c.drawString(40, y, "=== Vulnerability Results ===")
    y -= 16
    c.drawString(40, y, vuln_results.get("vuln_summary", ""))
    y -= 30

    c.drawString(40, y, "=== Mitigation Plan ===")
    y -= 16
    c.drawString(40, y, json.dumps(mitigation_plan.get("actions", [])))
    y -= 30

    c.showPage()
    c.save()
    return output_pdf_path
