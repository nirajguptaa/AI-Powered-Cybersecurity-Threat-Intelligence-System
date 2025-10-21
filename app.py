import streamlit as st
import pandas as pd
import plotly.express as px
import os
from dotenv import load_dotenv
from main import analyze_user_query, run_cybersecurity_analysis
import base64

# Load environment variables
load_dotenv()

# Streamlit configuration
st.set_page_config(page_title="AI Cybersecurity Threat Intelligence",
                   layout="wide",
                   page_icon="🛡️")

st.title("🛡️ AI-Powered Cybersecurity Threat Intelligence System")
st.markdown("""
This AI system uses Generative AI to analyze cybersecurity threats, detect vulnerabilities, and recommend mitigation strategies in real time.
""")

# -----------------------------
# User Input Section
# -----------------------------
st.header("🔍 Enter System Issue or Vulnerability")
user_query = st.text_input("Enter a vulnerability or cybersecurity issue (e.g., 'How do I secure my MacBook?')")

if "history" not in st.session_state:
    st.session_state.history = []

# Analyze button
if st.button("Analyze Threat"):
    if user_query.strip() == "":
        st.warning("⚠️ Please enter a query to analyze.")
    else:
        st.session_state.history.append({"query": user_query, "response": None})
        with st.spinner("🚀 Analyzing your query using AI agents..."):
            try:
                # Run analysis
                result_text = analyze_user_query(user_query)

                # Store response
                st.session_state.history[-1]["response"] = result_text

                # -----------------------------
                # Display Clean Markdown Output
                # -----------------------------
                st.subheader("📊 Cybersecurity Intelligence Report")
                st.markdown(result_text)

                # Download option
                def generate_txt(content):
                    return content.encode("utf-8")

                b64 = base64.b64encode(generate_txt(result_text)).decode()
                href = f'<a href="data:file/txt;base64,{b64}" download="cybersecurity_report.txt">📥 Download Full Report</a>'
                st.markdown(href, unsafe_allow_html=True)

            except Exception as e:
                st.error(f"❌ Error during analysis: {e}")

# -----------------------------
# Follow-up Query Section
# -----------------------------
# -----------------------------
# Follow-up Query Section
# -----------------------------
st.header("💬 Follow-up Questions")
new_query = st.text_input("Ask follow-up about the previous analysis:")

if st.button("Submit Follow-up"):
    if not st.session_state.history:
        st.warning("⚠️ No previous analysis found. Please analyze a query first.")
    else:
        last_response = st.session_state.history[-1]["response"]
        if new_query and last_response:
            st.markdown(f"**User:** {new_query}")
            st.info("🔎 Searching insights from previous results...")

            # Split previous report into lines
            lines = last_response.split("\n")
            matched_lines = [line for line in lines if any(word.lower() in line.lower() for word in new_query.split())]

            if matched_lines:
                st.success("✅ Found relevant section in the previous report:")
                st.markdown("\n".join(matched_lines))
            else:
                st.info("No exact match found. Using AI to generate follow-up answer...")
                # Call analyze_user_query again with previous report as context
                followup_prompt = f"Previous report:\n{last_response}\n\nUser follow-up question: {new_query}"
                followup_answer = analyze_user_query(followup_prompt)
                st.markdown(followup_answer)
        else:
            st.warning("Please enter a follow-up question.")

# -----------------------------
# Sidebar: Summary Stats
# -----------------------------
st.sidebar.header("📌 Summary Stats")
if st.session_state.history:
    total_queries = len(st.session_state.history)
    st.sidebar.metric("Total Queries Analyzed", total_queries)
    st.sidebar.markdown("🧠 System powered by **CrewAI + LangChain + Groq**")

# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.markdown("👨‍💻 Developed by **Niraj Kumar Gupta** | Generative AI for Cybersecurity Threat Intelligence")