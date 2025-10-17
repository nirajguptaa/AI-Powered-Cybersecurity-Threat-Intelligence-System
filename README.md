# 🚀 AI-Powered Cybersecurity Threat Intelligence System

Leveraging CrewAI, LangChain-Groq, and Exa API

## 🧠 Project Overview

This AI-Powered Cybersecurity Threat Intelligence System is a multi-agent Generative AI system designed to automate cyber threat analysis, vulnerability detection, and mitigation reporting.

It utilizes CrewAI for agent orchestration, LangChain-Groq models for reasoning and response generation, and the Exa API for real-time threat intelligence gathering from diverse online sources. The system generates detailed, human-readable analytical reports tailored for cybersecurity professionals.

## 🎯 Objectives

*   Automate threat intelligence collection from open and structured data sources.
*   Employ Generative AI agents for analysis, correlation, and prioritization of vulnerabilities (CVEs).
*   Provide actionable mitigation strategies based on AI reasoning.
*   Generate human-readable reports summarizing findings and recommendations.

## ⚙️ Key Technologies

| Technology        | Purpose                                                                 |
| :---------------- | :----------------------------------------------------------------------- |
| CrewAI            | Multi-agent coordination and task orchestration                         |
| LangChain-Groq    | LLM-based reasoning and response generation                             |
| Exa API           | Retrieval-Augmented Generation (RAG) for real-time cybersecurity search |
| Python 3.12       | Core development language                                               |
| `python-dotenv`   | Secure environment variable management                                  |
| VS Code           | Development environment                                                 |

## 🧩 System Architecture

The system employs a multi-agent framework where each agent fulfills a distinct role:

1.  **Threat Intelligence Collector:** Retrieves the latest CVEs, advisories, and security updates using the Exa API.
2.  **Vulnerability Researcher:** Analyzes collected vulnerabilities for severity, exploitability, and potential impact.
3.  **Incident Response Advisor:** Recommends mitigation steps, patch management strategies, and preventive measures.
4.  **Report Generator:** Compiles findings into structured and easily digestible threat reports.

## 🧮 Workflow

```text
User Input (Query / Use Case)
          ↓
Threat Intelligence Agent → Collects CVE data
          ↓
Vulnerability Researcher → Analyzes severity and impact
          ↓
Incident Response Agent → Suggests mitigation strategy
          ↓
Final Report → Generated with AI summarization
```

## 🧰 Installation & Setup

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/nirajguptaa/AI-Powered-Cybersecurity-Threat-Intelligence-System.git
    cd AI-Powered-Cybersecurity-Threat-Intelligence-System
    ```

2.  **Create Virtual Environment**

    ```bash
    python3 -m venv venv
    source venv/bin/activate   # for macOS/Linux
    venv\Scripts\activate      # for Windows
    ```

3.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Set Up Environment Variables**

    Create a `.env` file in the project root and add your API keys:

    ```
    GROQ_API_KEY=your_groq_api_key_here
    EXA_API_KEY=your_exa_api_key_here
    ```

## ▶️ Running the Project

After activating your virtual environment:

```bash
python main.py
 ```
 The system will:
- Fetch the latest vulnerabilities (CVEs)
- Analyze their severity and threat level
- Suggest mitigation and preventive measures
- Display the generated cybersecurity intelligence report

## AI Output Example: Latest Software Vulnerabilities (CVEs)
  ```
CVE-2023-25558: Apache HTTP Server 2.4.54 - RCE Vulnerability
Severity: Critical
Impact: System compromise, data breach
Mitigation: Update to Apache 2.4.57 or later

CVE-2023-25567: Debian Linux 11.4 - RCE Vulnerability
Severity: High
Impact: Unauthorized access
Mitigation: Apply vendor security patches immediately
  ```
## 🔒 Security Considerations
- All API keys and credentials must be stored securely in `.env` file.
- Sensitive files such as `.env`, `venv/`, and model checkpoints are ignored by `.gitignore`.
- Regularly regenerate API keys to prevent potential misuse.

## 🧑‍💻 Developer Information
- **Developer:** Niraj Kumar Gupta
- **Project Type:** Generative AI – Cybersecurity Intelligence

## 🧱 Future Enhancements
- Integration with SIEM tools like Splunk or QRadar.
- Dashboard UI for visualization of vulnerabilities and response timelines.
- Advanced threat prediction using LLM fine-tuning.
- Deployment as a web service or Slack bot for enterprise use.



