from crewai import Agent, Task #Collect threats from multiple sources automatically
from utils.exa_client import exa_client
from langchain_groq import ChatGroq

llm = ChatGroq(temperature=0, model_name="llama3-70b-8192")

def fetch_cybersecurity_threats(query="Latest cybersecurity threats 2024"):
    result = exa_client.search_and_contents(query, summary=True)
    threat_list = []
    if result.results:
        for item in result.results:
            threat_list.append({
                "title": getattr(item, "title", "No Title"),
                "url": getattr(item, "url", "#"),
                "published_date": getattr(item, "published_date", "Unknown Date"),
                "summary": getattr(item, "summary", "No Summary"),
            })
    return threat_list

threat_analyst = Agent(
    role="Cybersecurity Threat Intelligence Analyst",
    goal="Gather real-time cybersecurity threat intelligence.",
    backstory="You're an expert in cybersecurity, tracking emerging threats, malware campaigns, and hacking incidents.",
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=5,
    memory=True,
)

threat_analysis_task = Task(
    description="Use EXA API to retrieve the latest cybersecurity threats.",
    expected_output="Structured list of recent cybersecurity threats.",
    agent=threat_analyst,
    callback=lambda inputs: fetch_cybersecurity_threats(),
)