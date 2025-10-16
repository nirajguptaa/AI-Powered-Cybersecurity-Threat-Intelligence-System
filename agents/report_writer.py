from crewai import Agent, Task
from langchain_groq import ChatGroq

llm = ChatGroq(temperature=0, model_name="llama3-70b-8192")

cybersecurity_writer = Agent(
    role="Cybersecurity Report Writer",
    goal="Generate a structured cybersecurity report.",
    backstory="You're a leading analyst summarizing threats, vulnerabilities, and mitigation strategies.",
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=5,
    memory=True,
)

write_threat_report_task = Task(
    description="Summarize threat intelligence, vulnerabilities, and response strategies into a report.",
    expected_output="Comprehensive cybersecurity intelligence report.",
    agent=cybersecurity_writer,
    context=[],  # will link tasks later
)