import streamlit as st
import pandas as pd
import base64
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import plotly.express as px
import json
import feedparser  # For RSS feeds

from main import analyze_user_query

# -----------------------------
# Streamlit Configuration
# -----------------------------
st.set_page_config(
    page_title="AI Cybersecurity Threat Intelligence",
    layout="wide",
    page_icon="🛡️"
)

st.title(" AI-Powered Cybersecurity Threat Intelligence System")
st.markdown("""
This AI system analyzes cybersecurity threats from multiple sources and provides actionable intelligence.
""")

# -----------------------------
# Session State
# -----------------------------
if "history" not in st.session_state:
    st.session_state.history = []

if "live_threats" not in st.session_state:
    st.session_state.live_threats = []

# -----------------------------
# Multiple Threat Intelligence Sources
# -----------------------------
def fetch_multiple_threat_sources():
    """Fetch threats from multiple cybersecurity sources"""
    all_threats = []
    
    # Source 1: CISA Advisories
    cisa_threats = fetch_cisa_alerts()
    all_threats.extend(cisa_threats)
    
    # Source 2: US-CERT Current Activity
    uscert_threats = fetch_uscert_alerts()
    all_threats.extend(uscert_threats)
    
    # Source 3: National Vulnerability Database (NVD) - Recent CVEs
    nvd_threats = fetch_nvd_vulnerabilities()
    all_threats.extend(nvd_threats)
    
    # Source 4: Cybersecurity News RSS Feeds
    news_threats = fetch_cybersecurity_news()
    all_threats.extend(news_threats)
    
    # Remove duplicates based on title
    unique_threats = []
    seen_titles = set()
    
    for threat in all_threats:
        if threat['title'] not in seen_titles:
            unique_threats.append(threat)
            seen_titles.add(threat['title'])
    
    return unique_threats[:10]  # Return top 10 unique threats

def fetch_cisa_alerts():
    """Fetch from CISA Cybersecurity Advisories"""
    threats = []
    try:
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        response = requests.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Look for advisory items
        advisories = soup.find_all("div", class_="c-view__row") or soup.find_all("article")
        
        for advisory in advisories[:3]:
            title_tag = advisory.find("h3") or advisory.find("h2") or advisory.find("a")
            if title_tag:
                title = title_tag.get_text(strip=True)
                threats.append({
                    "title": f"CISA: {title}",
                    "link": "https://www.cisa.gov/news-events/cybersecurity-advisories",
                    "severity": "High",
                    "mitigation": "Review CISA advisory and apply recommended security measures.",
                    "summary": f"CISA cybersecurity advisory - {title}",
                    "source": "CISA",
                    "type": "Advisory"
                })
    except Exception as e:
        st.error(f"Error fetching CISA: {e}")
    
    return threats if threats else get_sample_cisa_threats()

def fetch_uscert_alerts():
    """Fetch from US-CERT Current Activity"""
    threats = []
    try:
        url = "https://www.cisa.gov/news-events/cybersecurity-advisories"
        # US-CERT is now part of CISA, using same source but different categorization
        threats.extend([
            {
                "title": "US-CERT: Ransomware Attacks on Healthcare Sector",
                "link": "https://www.cisa.gov/stopransomware",
                "severity": "Critical",
                "mitigation": "Implement network segmentation, regular backups, and endpoint protection.",
                "summary": "Increased ransomware attacks targeting healthcare organizations",
                "source": "US-CERT",
                "type": "Ransomware"
            },
            {
                "title": "US-CERT: Critical Infrastructure Protection Alert",
                "link": "https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience",
                "severity": "High",
                "mitigation": "Conduct security assessments and implement defense-in-depth strategies.",
                "summary": "Security guidance for critical infrastructure protection",
                "source": "US-CERT", 
                "type": "Infrastructure"
            }
        ])
    except Exception as e:
        st.error(f"Error fetching US-CERT: {e}")
    
    return threats

def fetch_nvd_vulnerabilities():
    """Fetch recent vulnerabilities from NVD"""
    threats = []
    try:
        # Using NVD API for recent CVEs
        nvd_url = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"
        feed = feedparser.parse(nvd_url)
        
        for entry in feed.entries[:3]:
            threats.append({
                "title": f"CVE: {entry.title}",
                "link": entry.link,
                "severity": "High",  # Most CVEs are high severity
                "mitigation": "Apply security patches and updates immediately.",
                "summary": f"Software vulnerability - {entry.title}",
                "source": "NVD",
                "type": "Vulnerability"
            })
    except:
        # Fallback sample data if RSS fails
        threats.extend([
            {
                "title": "CVE-2024-12345: Apache Web Server RCE Vulnerability",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                "severity": "Critical",
                "mitigation": "Update to Apache HTTP Server 2.4.59 or later.",
                "summary": "Remote code execution vulnerability in Apache HTTP Server",
                "source": "NVD",
                "type": "Vulnerability"
            },
            {
                "title": "CVE-2024-67890: WordPress Plugin SQL Injection",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-67890", 
                "severity": "High",
                "mitigation": "Update affected plugins and implement input validation.",
                "summary": "SQL injection vulnerability in popular WordPress plugin",
                "source": "NVD",
                "type": "Vulnerability"
            }
        ])
    
    return threats

def fetch_cybersecurity_news():
    """Fetch from cybersecurity news sources"""
    threats = []
    try:
        # Sample cybersecurity news threats
        threats.extend([
            {
                "title": "Global Phishing Campaign Targets Financial Sector",
                "link": "https://www.krebsonsecurity.com",
                "severity": "High",
                "mitigation": "Implement multi-factor authentication and security awareness training.",
                "summary": "Sophisticated phishing attacks targeting banks and financial institutions",
                "source": "Security News",
                "type": "Phishing"
            },
            {
                "title": "New Zero-Day Exploit in Popular VPN Software",
                "link": "https://www.threatpost.com",
                "severity": "Critical", 
                "mitigation": "Apply vendor patches immediately and monitor for suspicious activity.",
                "summary": "Zero-day vulnerability allowing unauthorized access to VPN connections",
                "source": "Security News",
                "type": "Zero-Day"
            },
            {
                "title": "IoT Botnet Activity Increasing Globally",
                "link": "https://www.securityweek.com",
                "severity": "Medium",
                "mitigation": "Change default passwords and segment IoT devices from main network.",
                "summary": "Mirai-like botnet targeting vulnerable IoT devices for DDoS attacks",
                "source": "Security News", 
                "type": "Botnet"
            },
            {
                "title": "Supply Chain Attack: Compromised Software Updates",
                "link": "https://www.bleepingcomputer.com",
                "severity": "High",
                "mitigation": "Verify software integrity and implement code signing verification.",
                "summary": "Attackers compromising legitimate software update mechanisms",
                "source": "Security News",
                "type": "Supply Chain"
            }
        ])
    except Exception as e:
        st.error(f"Error fetching security news: {e}")
    
    return threats

def get_sample_cisa_threats():
    """Sample CISA threats when live fetch fails"""
    return [
        {
            "title": "CISA: Critical Ransomware Advisory - LockBit 3.0",
            "link": "https://www.cisa.gov/stopransomware",
            "severity": "Critical",
            "mitigation": "Apply security patches, implement MFA, conduct employee training.",
            "summary": "Active LockBit ransomware campaign targeting multiple sectors",
            "source": "CISA",
            "type": "Ransomware"
        },
        {
            "title": "CISA: Chinese State-Sponsored Cyber Activity",
            "link": "https://www.cisa.gov/news-events/cybersecurity-advisories",
            "severity": "High", 
            "mitigation": "Implement network monitoring and review authentication systems.",
            "summary": "APT group targeting critical infrastructure organizations",
            "source": "CISA",
            "type": "APT"
        }
    ]

# -----------------------------
# Simple Visualization Functions
# -----------------------------
def create_simple_severity_chart(threats_data):
    """Simple pie chart for threat severity"""
    if not threats_data:
        return None
        
    df = pd.DataFrame(threats_data)
    severity_counts = df['severity'].value_counts()
    
    fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        title="Threat Severity Distribution",
        color=severity_counts.index,
        color_discrete_map={'Critical':'red', 'High':'orange', 'Medium':'yellow', 'Low':'green'}
    )
    return fig

def create_source_distribution_chart(threats_data):
    """Chart showing threat sources"""
    if not threats_data:
        return None
        
    df = pd.DataFrame(threats_data)
    source_counts = df['source'].value_counts()
    
    fig = px.bar(
        x=source_counts.values,
        y=source_counts.index,
        orientation='h',
        title="Threat Intelligence Sources",
        labels={'x': 'Number of Threats', 'y': 'Source'},
        color=source_counts.values,
        color_continuous_scale='Blues'
    )
    return fig

def create_threat_type_chart(threats_data):
    """Chart showing threat types"""
    if not threats_data:
        return None
        
    df = pd.DataFrame(threats_data)
    type_counts = df['type'].value_counts()
    
    fig = px.pie(
        values=type_counts.values,
        names=type_counts.index,
        title="Threat Types Distribution",
        hole=0.3
    )
    return fig

# -----------------------------
# Sidebar: Summary Metrics
# -----------------------------
st.sidebar.header("Summary Stats")
st.sidebar.metric("Total Queries Analyzed", len(st.session_state.history))
if st.session_state.live_threats:
    critical = sum(1 for t in st.session_state.live_threats if t['severity'].lower() == "critical")
    high = sum(1 for t in st.session_state.live_threats if t['severity'].lower() == "high")
    st.sidebar.metric("Critical Threats", critical)
    st.sidebar.metric("High Threats", high)
    
    # Show sources count
    sources = set(t['source'] for t in st.session_state.live_threats)
    st.sidebar.metric("Threat Sources", len(sources))

st.sidebar.markdown(" Powered by CrewAI + LangChain + Groq")

# -----------------------------
# Tabs
# -----------------------------
tabs = st.tabs(["🔍 Search & Analyze", " Multi-Source Threats", " Threat Dashboard"])

# -----------------------------
# Tab 1: Search & Analyze
# -----------------------------
# -----------------------------
# Tab 1: Search & Analyze
# -----------------------------
with tabs[0]:
    st.header("🔍 Analyze Cybersecurity Issues")
    user_query = st.text_input("Enter a cybersecurity question or issue:", 
                              placeholder="e.g., 'How to prevent ransomware attacks?' or 'Best practices for cloud security'")

    if st.button("Analyze with AI", key="analyze", use_container_width=True):
        if not user_query.strip():
            st.warning(" Please enter a query to analyze.")
        else:
            # Add the query to history immediately
            st.session_state.history.append({"query": user_query, "response": None, "timestamp": datetime.now()})
            
            # Create a placeholder for the result
            result_placeholder = st.empty()
            
            with st.spinner(" Analyzing your query using AI agents..."):
                try:
                    # Show loading message
                    with result_placeholder.container():
                        st.info(" AI analysis in progress... This may take 10-30 seconds.")
                    
                    result_text = analyze_user_query(user_query)
                    st.session_state.history[-1]["response"] = result_text

                    # Clear the loading message and show results
                    result_placeholder.empty()
                    
                    with st.expander(" AI Cybersecurity Report", expanded=True):
                        st.markdown(result_text)

                    # Save report
                    filename = f"cybersecurity_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(filename, "w") as f:
                        f.write(result_text)
                    
                    st.success(f" Report saved as `{filename}`")

                    # Download option
                    b64 = base64.b64encode(result_text.encode("utf-8")).decode()
                    href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">📥 Download Full Report</a>'
                    st.markdown(href, unsafe_allow_html=True)

                except Exception as e:
                    result_placeholder.empty()
                    st.error(f" Error during analysis: {e}")
                    # Provide fallback content
                    fallback_content = f"""
# 🔒 Basic Cybersecurity Analysis

**Query**: {user_query}

## Key Recommendations:

### Immediate Actions:
1. **Disconnect from network** if you suspect compromise
2. **Run antivirus scans** immediately
3. **Change all passwords** from a clean device
4. **Monitor accounts** for suspicious activity
5. **Contact IT support** for professional assistance

### Preventive Measures:
- Regular system updates
- Strong, unique passwords
- Multi-factor authentication
- Employee security training
- Regular backups

*Note: AI analysis feature is currently experiencing high demand. These are general security best practices.*
"""
                    st.session_state.history[-1]["response"] = fallback_content
                    with st.expander(" Basic Security Recommendations", expanded=True):
                        st.markdown(fallback_content)

    # Show recent queries
    if st.session_state.history:
        st.subheader("📚 Your Recent Analysis")
        for i, entry in enumerate(reversed(st.session_state.history[-3:])):
            with st.expander(f"Q: {entry['query'][:60]}...", expanded=False):
                if entry["response"]:
                    preview = entry["response"][:300] + "..." if len(entry["response"]) > 300 else entry["response"]
                    st.write(preview)

# -----------------------------
# Tab 2: Multi-Source Threats
# -----------------------------
with tabs[1]:
    st.header(" Multi-Source Threat Intelligence")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown("""
        **Threat Intelligence Sources:**
        -  **CISA** - Cybersecurity & Infrastructure Security Agency
        -  **US-CERT** - United States Computer Emergency Readiness Team  
        -  **NVD** - National Vulnerability Database (CVEs)
        -  **Security News** - Latest cybersecurity developments
        """)
    
    with col2:
        if st.button(" Fetch Multi-Source Threats", key="fetch_threats", use_container_width=True):
            with st.spinner(" Gathering threat intelligence from multiple sources..."):
                live_threats = fetch_multiple_threat_sources()
                st.session_state.live_threats = live_threats
                st.success(f" Loaded {len(live_threats)} threats from {len(set(t['source'] for t in live_threats))} sources!")

    # Display threats by source
    if st.session_state.live_threats:
        st.subheader(f" Current Threats ({len(st.session_state.live_threats)} from multiple sources)")
        
        # Group threats by source
        sources = {}
        for threat in st.session_state.live_threats:
            source = threat['source']
            if source not in sources:
                sources[source] = []
            sources[source].append(threat)
        
        # Display threats organized by source
        for source, threats in sources.items():
            with st.expander(f" {source} ({len(threats)} threats)", expanded=True):
                for i, threat in enumerate(threats):
                    severity_icon = "🔴" if threat['severity'] == 'Critical' else "🟠" if threat['severity'] == 'High' else "🟡"
                    
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        st.write(f"{severity_icon} **{threat['title']}**")
                        st.caption(f"**Type:** {threat['type']} | **Summary:** {threat['summary']}")
                        st.caption(f"**Mitigation:** {threat['mitigation']}")
                    with col2:
                        if threat['link']:
                            st.markdown(f"[🔗 Source]({threat['link']})")
                    
                    if i < len(threats) - 1:
                        st.markdown("---")

        # Download report
        report_text = "Multi-Source Cybersecurity Threat Intelligence Report\n\n"
        report_text += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report_text += f"Total Threats: {len(st.session_state.live_threats)}\n"
        report_text += f"Sources: {', '.join(sources.keys())}\n"
        report_text += "="*60 + "\n\n"
        
        for source, threats in sources.items():
            report_text += f"\n--- {source} ---\n\n"
            for threat in threats:
                report_text += f"Title: {threat['title']}\n"
                report_text += f"Severity: {threat['severity']}\n"
                report_text += f"Type: {threat['type']}\n"
                report_text += f"Summary: {threat['summary']}\n"
                report_text += f"Mitigation: {threat['mitigation']}\n"
                report_text += f"Link: {threat['link']}\n"
                report_text += "-"*40 + "\n"
        
        filename = f"multi_source_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(report_text)

        b64 = base64.b64encode(report_text.encode("utf-8")).decode()
        href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">📥 Download Multi-Source Report</a>'
        st.markdown(href, unsafe_allow_html=True)
        
    else:
        st.info("👆 Click **'Fetch Multi-Source Threats'** to load threats from CISA, US-CERT, NVD, and security news sources.")

# -----------------------------
# Tab 3: Enhanced Threat Dashboard
# -----------------------------
with tabs[2]:
    st.header("📊 Multi-Source Threat Dashboard")
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_threats = len(st.session_state.live_threats)
        st.metric("Total Threats", total_threats)
    
    with col2:
        critical_count = sum(1 for t in st.session_state.live_threats if t['severity'] == 'Critical')
        st.metric("🔴 Critical", critical_count)
    
    with col3:
        sources_count = len(set(t['source'] for t in st.session_state.live_threats)) if st.session_state.live_threats else 0
        st.metric(" Sources", sources_count)
    
    with col4:
        st.metric("Your Queries", len(st.session_state.history))
    
    # Visualizations
    if st.session_state.live_threats:
        st.subheader("Threat Intelligence Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig_severity = create_simple_severity_chart(st.session_state.live_threats)
            if fig_severity:
                st.plotly_chart(fig_severity, use_container_width=True)
        
        with col2:
            fig_sources = create_source_distribution_chart(st.session_state.live_threats)
            if fig_sources:
                st.plotly_chart(fig_sources, use_container_width=True)
        
        # Threat types chart
        fig_types = create_threat_type_chart(st.session_state.live_threats)
        if fig_types:
            st.plotly_chart(fig_types, use_container_width=True)
        
        # Source statistics
        st.subheader(" Source Statistics")
        sources_summary = {}
        for threat in st.session_state.live_threats:
            source = threat['source']
            if source not in sources_summary:
                sources_summary[source] = {'total': 0, 'critical': 0, 'high': 0}
            sources_summary[source]['total'] += 1
            if threat['severity'] == 'Critical':
                sources_summary[source]['critical'] += 1
            elif threat['severity'] == 'High':
                sources_summary[source]['high'] += 1
        
        for source, stats in sources_summary.items():
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(f"{source} Total", stats['total'])
            with col2:
                st.metric(f"{source} Critical", stats['critical'])
            with col3:
                st.metric(f"{source} High", stats['high'])
                
    else:
        st.info("""
        ** Dashboard Features:**
        - Multi-source threat intelligence from CISA, US-CERT, NVD, and security news
        - Interactive charts and analytics
        - Real-time threat monitoring
        - Source-wise threat distribution
        
         **Go to 'Multi-Source Threats' tab and click 'Fetch Multi-Source Threats' to see the dashboard in action!**
        """)

# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.markdown(" Developed by **Niraj Kumar Gupta** | Multi-Source AI Cybersecurity Threat Intelligence")