# app.py
import os
import tempfile

import streamlit as st
from pypdf import PdfReader

from agents_runner import (
    run_threat_collector,
    run_vuln_analysis,
    run_mitigation_strategist,
    generate_report,
)

# ================== Setup ==================
st.set_page_config(page_title="Cybermind Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Cybermind — AI-powered Cybersecurity Intelligence")
st.caption("Upload your security data → it runs through 4 agents → get a final PDF → ask questions about it.")

# Prefer Streamlit Secrets, then fall back to environment
OPENAI_KEY = st.secrets.get("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")

with st.sidebar:
    st.subheader("How to use")
    st.markdown(
        "1) Upload one or more files (logs/CSV/JSON)\n"
        "2) Click **Analyze & Generate Report**\n"
        "3) Download the **PDF**\n"
        "4) Ask questions about the report in **Q&A**"
    )
    st.divider()
    st.markdown("**Tip:** Start with a small file to test the flow.")

# ================== Upload ==================
st.header("1) Upload your data")
uploaded_files = st.file_uploader(
    "Upload one or more files (any type to start)",
    accept_multiple_files=True
)
run_button = st.button("Analyze & Generate Report 🚀")

# ================== Session State ==================
if "report_bytes" not in st.session_state:
    st.session_state.report_bytes = None
if "report_text" not in st.session_state:
    st.session_state.report_text = ""

def extract_pdf_text_from_bytes(pdf_bytes: bytes) -> str:
    """Write bytes to a temp PDF and extract text for Q&A context."""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(pdf_bytes)
        tmp.flush()
        path = tmp.name
    try:
        reader = PdfReader(path)
        all_text = ""
        for page in reader.pages:
            try:
                all_text += (page.extract_text() or "") + "\n"
            except Exception:
                pass
        return all_text
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

# ================== Pipeline ==================
if run_button:
    if not uploaded_files:
        st.error("Please upload at least one file first.")
    else:
        with st.spinner("Running Cybermind pipeline..."):
            # 1) Threat Collector
            st.subheader("🔍 Threat Collector Agent")
            threat_data = run_threat_collector(uploaded_files)
            st.json(threat_data)

            # 2) Vulnerability Analysis
            st.subheader("🧪 Vulnerability Analysis Agent")
            vuln_results = run_vuln_analysis(threat_data)  # make sure agents_runner expects only threat_data
            st.json(vuln_results)

            # 3) Mitigation Strategist
            st.subheader("🛡️ Mitigation Strategist Agent")
            mitigation_plan = run_mitigation_strategist(vuln_results)
            st.json(mitigation_plan)

            # 4) Report Generator
            st.subheader("📄 Report Generator Agent")
            with tempfile.TemporaryDirectory() as tmpdir:
                output_pdf = os.path.join(tmpdir, "cybermind_report.pdf")
                pdf_path = generate_report(threat_data, vuln_results, mitigation_plan, output_pdf)
                with open(pdf_path, "rb") as f:
                    st.session_state.report_bytes = f.read()

            st.success("Pipeline finished successfully ✅")

            # Extract text for Q&A
            st.session_state.report_text = extract_pdf_text_from_bytes(st.session_state.report_bytes)
            if st.session_state.report_text.strip():
                st.info("Report text extracted for Q&A.")
            else:
                st.warning("No text could be extracted from the PDF. Q&A may be limited.")

# ================== Download + Q&A (RAG-lite) ==================
st.header("2) Download report & Q&A")
if st.session_state.report_bytes:
    st.download_button(
        label="⬇️ Download Cybermind Report (PDF)",
        data=st.session_state.report_bytes,
        file_name="cybermind_report.pdf",
        mime="application/pdf"
    )

    st.subheader("💬 Q&A about the report")
    question = st.text_input("Ask a question about this report:")
    txt = st.session_state.report_text or ""

    if question:
        if not txt.strip():
            st.warning("No text extracted from the PDF to answer from.")
        else:
            if OPENAI_KEY:
                # Use OpenAI for smart answers (RAG-lite)
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=OPENAI_KEY)

                    # Limit context length to keep prompt size reasonable
                    context = txt[:6000]

                    with st.spinner("Thinking with AI... 🤖"):
                        resp = client.chat.completions.create(
                            model="gpt-4o-mini",  # change if you set OPENAI_MODEL in Secrets
                            messages=[
                                {
                                    "role": "system",
                                    "content": (
                                        "You are a helpful cybersecurity analyst. "
                                        "Answer based ONLY on the report content. "
                                        "If the answer isn't in the report, say so briefly."
                                    ),
                                },
                                {
                                    "role": "user",
                                    "content": f"Report content:\n{context}\n\nQuestion: {question}",
                                },
                            ],
                            temperature=0.2,
                        )
                    answer = resp.choices[0].message.content.strip()
                    st.markdown("**Answer (AI-generated):**")
                    st.write(answer)
                except Exception as e:
                    st.error(f"Q&A engine error: {e}")
            else:
                # Fallback: simple keyword-based search
                q_tokens = [t.lower() for t in question.split() if len(t) > 2]
                best_para, best_score = "", -1
                for para in txt.split("\n\n"):
                    score = sum(para.lower().count(t) for t in q_tokens)
                    if score > best_score:
                        best_score, best_para = score, para
                st.markdown("**Answer (from report text, keyword match):**")
                st.write(best_para if best_para.strip() else "I couldn't find a clear answer in the report.")
else:
    st.info("Run the analysis first to generate the report.")
