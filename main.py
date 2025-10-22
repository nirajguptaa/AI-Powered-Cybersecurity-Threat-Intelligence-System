import os
from dotenv import load_dotenv
from crewai import Crew, Process, Task
from langchain_groq import ChatGroq
from typing import Dict, List, Optional
import json
from datetime import datetime

# Load agents and tasks
from agents.threat_analyst import threat_analyst, threat_analysis_task
from agents.vulnerability_researcher import vulnerability_researcher, vulnerability_research_task
from agents.incident_response import incident_response_advisor, incident_response_task
from agents.report_writer import cybersecurity_writer, write_threat_report_task

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
EXA_API_KEY = os.getenv("EXA_API_KEY")

# Initialize LLM
llm = ChatGroq(temperature=0, model_name="llama-3.1-8b-instant")

# Assign the same LLM to all agents
for agent in [threat_analyst, vulnerability_researcher, incident_response_advisor, cybersecurity_writer]:
    agent.llm = llm

# Link tasks
incident_response_task.context = [threat_analysis_task, vulnerability_research_task]
write_threat_report_task.context = [threat_analysis_task, vulnerability_research_task, incident_response_task]

# Initialize Crew
crew = Crew(
    agents=[threat_analyst, vulnerability_researcher, incident_response_advisor, cybersecurity_writer],
    tasks=[threat_analysis_task, vulnerability_research_task, incident_response_task, write_threat_report_task],
    verbose=2,
    process=Process.sequential,
    full_output=True,
    share_crew=False,
    manager_llm=llm,
    max_iter=15,
)

# 🔹 Run the full crew process for main execution
def run_cybersecurity_analysis():
    results = crew.kickoff()
    return results

# 🔹 Quick Analysis Function
def get_quick_analysis(user_query: str) -> str:
    """
    Generate a quick cybersecurity analysis for immediate insights.
    """
    quick_task = Task(
        description=f"Provide a concise cybersecurity analysis for: '{user_query}'. "
                    f"Focus on immediate risks, top 3 mitigation steps, and urgency level. "
                    f"Keep response under 300 words.",
        expected_output="A brief but actionable cybersecurity advisory with urgency rating and immediate steps.",
        agent=threat_analyst,
    )

    quick_crew = Crew(
        agents=[threat_analyst],
        tasks=[quick_task],
        verbose=1,
        process=Process.sequential,
        manager_llm=llm,
    )

    result = quick_crew.kickoff()
    return str(result).strip()

# 🔹 Threat Intelligence Briefing
def get_threat_intelligence_brief(threats: List[Dict]) -> str:
    """
    Generate a comprehensive threat intelligence brief from collected threats.
    """
    threats_json = json.dumps(threats, indent=2)
    
    brief_task = Task(
        description=f"Analyze these current cybersecurity threats and create an executive brief: {threats_json}. "
                    f"Provide: 1) Executive Summary, 2) Top 3 Critical Threats, 3) Industry Impact Analysis, "
                    f"4) Recommended Immediate Actions, 5) Strategic Recommendations.",
        expected_output="A comprehensive threat intelligence brief in markdown format for security leadership.",
        agent=cybersecurity_writer,
    )

    brief_crew = Crew(
        agents=[cybersecurity_writer, threat_analyst],
        tasks=[brief_task],
        verbose=1,
        process=Process.sequential,
        manager_llm=llm,
    )

    result = brief_crew.kickoff()
    return str(result).strip()

# 🔹 Dynamic User Query Analysis Function
def analyze_user_query(user_query: str, analysis_type: str = "comprehensive") -> str:
    """
    Generate a comprehensive cybersecurity report for a user query.
    """
    print(f"Analyzing user query: {user_query}")

    if analysis_type == "quick":
        return get_quick_analysis(user_query)

    dynamic_task = Task(
        description=f"Generate a comprehensive cybersecurity intelligence report for: '{user_query}'. "
                    f"Include: Executive Summary, Threat Landscape Analysis, Vulnerability Assessment, "
                    f"Risk Scoring (1-10), Immediate Mitigation Steps, Long-term Security Recommendations, "
                    f"Compliance Considerations, and Implementation Timeline.",
        expected_output="A detailed and structured cybersecurity report in Markdown format with risk scoring.",
        agent=cybersecurity_writer,
    )

    dynamic_crew = Crew(
        agents=[cybersecurity_writer, threat_analyst, vulnerability_researcher, incident_response_advisor],
        tasks=[dynamic_task],
        verbose=2,
        process=Process.sequential,
        manager_llm=llm,
    )

    result = dynamic_crew.kickoff()

    # Handle result safely
    if isinstance(result, dict):
        final_output = result.get("final_output", "⚠️ No report generated.")
        task_outputs = result.get("tasks_outputs", [])
        detailed_text = "\n\n".join(
            t.exported_output if hasattr(t, "exported_output") else str(t)
            for t in task_outputs
        )
        # Combine summary + detailed sections
        return f"## Comprehensive Cybersecurity Intelligence Report\n\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n{final_output}\n\n---\n## 📋 Detailed Analysis:\n{detailed_text}".strip()
    else:
        return str(result).strip()

# 🔹 Vulnerability Assessment Function
def assess_vulnerability(cve_id: str = None, software_name: str = None) -> str:
    """
    Specialized function for vulnerability assessment.
    """
    target = cve_id if cve_id else software_name
    vuln_task = Task(
        description=f"Conduct deep vulnerability assessment for: {target}. "
                    f"Provide: CVSS scoring, exploit availability, patch status, "
                    f"workarounds, and detection signatures.",
        expected_output="Technical vulnerability assessment with actionable remediation guidance.",
        agent=vulnerability_researcher,
    )

    vuln_crew = Crew(
        agents=[vulnerability_researcher, incident_response_advisor],
        tasks=[vuln_task],
        verbose=1,
        process=Process.sequential,
        manager_llm=llm,
    )

    result = vuln_crew.kickoff()
    return str(result).strip()

# 🔹 Compliance Check Function
def check_compliance(framework: str = "NIST") -> str:
    """
    Check compliance against security frameworks.
    """
    compliance_task = Task(
        description=f"Analyze current threat landscape against {framework} cybersecurity framework. "
                    f"Identify compliance gaps and provide remediation roadmap.",
        expected_output=f"{framework} compliance assessment with gap analysis and remediation plan.",
        agent=cybersecurity_writer,
    )

    compliance_crew = Crew(
        agents=[cybersecurity_writer, threat_analyst],
        tasks=[compliance_task],
        verbose=1,
        process=Process.sequential,
        manager_llm=llm,
    )

    result = compliance_crew.kickoff()
    return str(result).strip()

# 🔹 Main Execution Block
if __name__ == "__main__":
    # Example usage of different functions
    print("🧠 AI Cybersecurity Threat Intelligence System")
    print("=" * 50)
    
    # Test quick analysis
    quick_result = get_quick_analysis("How to secure remote work environment?")
    print("\n⚡ Quick Analysis Result:")
    print(quick_result)
    
    # Test comprehensive analysis
    comprehensive_result = analyze_user_query("Ransomware protection strategies for healthcare organizations")
    print("\n📊 Comprehensive Analysis Result:")
    print(comprehensive_result)
    
    # Save reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    with open(f"quick_analysis_{timestamp}.txt", "w") as f:
        f.write(quick_result)
    
    with open(f"comprehensive_report_{timestamp}.txt", "w") as f:
        f.write(comprehensive_result)
    
    print(f"\n✅ Reports saved with timestamp: {timestamp}")