import os
from dotenv import load_dotenv
from crewai import Crew, Process
from langchain_groq import ChatGroq

# Load all agents and tasks
from agents.threat_analyst import threat_analyst, threat_analysis_task
from agents.vulnerability_researcher import vulnerability_researcher, vulnerability_research_task
from agents.incident_response import incident_response_advisor, incident_response_task
from agents.report_writer import cybersecurity_writer, write_threat_report_task

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
EXA_API_KEY = os.getenv("EXA_API_KEY")



# Initialize LLM for Crew manager with valid model
llm = ChatGroq(temperature=0, model_name="llama-3.1-8b-instant")

# Assign the same LLM to all agents explicitly
for agent in [threat_analyst, vulnerability_researcher, incident_response_advisor, cybersecurity_writer]:
    agent.llm = llm

# Link context for dependent tasks
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

# Run Crew
results = crew.kickoff()

# Save final report
with open("cybersecurity_report.txt", "w") as f:
    f.write(results['final_output'])

# Optional: display report in Jupyter/Colab
try:
    from IPython.display import display, Markdown
    display(Markdown(results['final_output']))
except ImportError:
    print(results['final_output'])