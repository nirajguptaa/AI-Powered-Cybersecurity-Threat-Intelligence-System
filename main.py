import os
from dotenv import load_dotenv
from crewai import Crew, Process, Task
from langchain_groq import ChatGroq

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

# Link tasks (dependencies)
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

# 🔹 Full Threat Analysis
def run_cybersecurity_analysis():
    results = crew.kickoff()
    return results


# 🔹 Dynamic User Query Analysis Function (fixed)
def analyze_user_query(user_query: str):
    """
    Analyze a user-provided cybersecurity question or issue dynamically.
    Example: 'How do I secure my MacBook?'
    """
    print(f"Analyzing user query: {user_query}")

    dynamic_task = Task(
        description=f"Analyze and provide a detailed cybersecurity response for: '{user_query}'. "
                    f"Include possible vulnerabilities, recommended configurations, and best practices.",
        expected_output="A clear and actionable security report for the given user query.",
        agent=cybersecurity_writer,
    )

    dynamic_crew = Crew(
        agents=[cybersecurity_writer],
        tasks=[dynamic_task],
        verbose=2,
        process=Process.sequential,
        manager_llm=llm,
    )

    result = dynamic_crew.kickoff()

    # ✅ Safe parsing (handle dict or string)
    if isinstance(result, dict):
        final_output = result.get("final_output", "⚠️ No summarized report found.")
        task_outputs = result.get("tasks_outputs", [])
        detailed_text = "\n\n".join(
            t.exported_output if hasattr(t, "exported_output") else str(t)
            for t in task_outputs
        )
        return f"{final_output}\n\n---\n📋 Detailed Analysis:\n{detailed_text}".strip()
    else:
        return str(result).strip()


# 🔹 Main Execution
if __name__ == "__main__":
    results = run_cybersecurity_analysis()

    # Save the report
    with open("cybersecurity_report.txt", "w") as f:
        if isinstance(results, dict):
            f.write(results.get('final_output', 'No output generated.'))
        else:
            f.write(str(results))

    # Display result
    print("\n🧠 Final Cybersecurity Report:\n")
    print(results.get('final_output', 'No report available.') if isinstance(results, dict) else results)