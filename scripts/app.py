import streamlit as st
import pandas as pd
import plotly.express as px
from threat_engine import ThreatIntelPipeline

st.set_page_config(
    page_title="SSH Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SSH Honeypot Threat Intelligence Dashboard")
st.caption("Live adversary telemetry, credential brute-force analytics, and MITRE ATT&CK behavioral classification.")

# Dynamic path resolution to data/sample_cowrie.json
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_PATH = BASE_DIR / "data" / "sample_cowrie.json"

@st.cache_data
def load_data():
    pipeline = ThreatIntelPipeline(str(LOG_PATH))
    sessions, auths, cmds = pipeline.parse()
    return sessions, pd.DataFrame(auths), pd.DataFrame(cmds)

try:
    sessions, df_auth, df_cmd = load_data()
except Exception as e:
    st.error(f"Error loading logs: {e}")
    st.stop()

#  KPI Metrics
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Total Sessions", len(sessions))
kpi2.metric("Brute-Force Attempts", len(df_auth) if not df_auth.empty else 0)
kpi3.metric("Shell Commands Run", len(df_cmd) if not df_cmd.empty else 0)
kpi4.metric("Unique Attacking IPs", df_auth["src_ip"].nunique() if not df_auth.empty else 0)

st.divider()

# Credential Stuffing Visuals
st.subheader("Credential Stuffing Analytics")
c1, c2 = st.columns(2)

if not df_auth.empty:
    with c1:
        top_users = df_auth["username"].value_counts().head(8).reset_index()
        top_users.columns = ["Username", "Attempts"]
        fig_user = px.bar(
            top_users, x="Attempts", y="Username", orientation="h",
            title="Most Targeted Usernames", color="Attempts",
            color_continuous_scale="Reds"
        )
        st.plotly_chart(fig_user, use_container_width=True)

    with c2:
        top_passwords = df_auth["password"].value_counts().head(8).reset_index()
        top_passwords.columns = ["Password", "Attempts"]
        fig_pass = px.bar(
            top_passwords, x="Attempts", y="Password", orientation="h",
            title="Top Attempted Passwords", color="Attempts",
            color_continuous_scale="Oranges"
        )
        st.plotly_chart(fig_pass, use_container_width=True)
else:
    st.info("No login attempts recorded yet.")

st.divider()

# MITRE ATT&CK Mapping & Raw Timeline
st.subheader("MITRE ATT&CK Behavioral Mapping")
c3, c4 = st.columns([1, 1])

if not df_cmd.empty:
    with c3:
        all_tags = []
        for tags in df_cmd["mitre_tags"]:
            all_tags.extend(tags)

        if all_tags:
            tag_series = pd.Series(all_tags).value_counts().reset_index()
            tag_series.columns = ["Technique", "Hits"]
            fig_mitre = px.pie(
                tag_series, names="Technique", values="Hits",
                title="Observed ATT&CK Techniques Breakdown", hole=0.4
            )
            st.plotly_chart(fig_mitre, use_container_width=True)
        else:
            st.info("Commands captured, but none matched current signature rules.")

    with c4:
        st.write("##### Intercepted Command Timeline")
        st.dataframe(df_cmd[["timestamp", "command", "mitre_tags"]], use_container_width=True)
else:
    st.info("No interactive commands recorded yet.")
