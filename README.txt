# Sybermind Dashboard

This project is an interactive dashboard built using Streamlit that connects four cybersecurity agents:
- Threat Collector Agent  
- Vulnerability Analysis Agent  
- Mitigation Strategist Agent  
- Report Generator Agent  

The main idea is that the user uploads a data file, and the system passes it through all four agents in order.  
At the end, a PDF report is generated that includes the results, and the user can ask questions (Q&A) about the content of the report directly from the dashboard.

## How to Run (Locally)
1. Install the required packages:
   pip install -r requirements.txt
2. Run the project:
   streamlit run app.py
3. After running, open the link shown in the terminal (usually http://localhost:8501)

## Deployment
You can also deploy this project online by uploading it to GitHub and then publishing it using Streamlit Cloud.

## Notes
- The project is still in its first experimental version.  
- Later, I will integrate the real Jupyter notebooks for each agent.

This project is part of my work on developing an AI-powered cybersecurity intelligence framework called Sybermind.