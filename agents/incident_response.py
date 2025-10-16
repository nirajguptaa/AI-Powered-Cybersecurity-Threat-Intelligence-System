from crewai import Agent, Task
from langchain_groq import ChatGroq

llm = ChatGroq(temperature=0, model_name="llama3-70b-8192")

incident_response_advisor = Agent(
    role="Incident Response Advisor",
    goal="Provide mitigation strategies for detected threats.",
    backstory="You specialize in cybersecurity defense strategies and incident response.",
    verbose=True,
    allow_delegation=False,
    llm=llm,
    max_iter=5,
    memory=True,
)

incident_response_task = Task(
    description="Analyze threats and vulnerabilities to suggest mitigation strategies.",
    expected_output="List of recommended defensive actions.",
    agent=incident_response_advisor,
    context=[],  # will link tasks later
)