import streamlit as st
import pandas as pd
from detect_attacks import detect_attacks

# Set page config
st.set_page_config(
    page_title="Cyber Threat Intel",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Title
st.title("🔒 Cyber Threat Intelligence System")
st.markdown("### HackNex 2026 - Multi-Stage Attack Detection")

# Sidebar
st.sidebar.header("📁 Upload Logs")
uploaded_file = st.sidebar.file_uploader("Choose CSV file", type="csv")

# Main area
if uploaded_file is not None:
    # Save uploaded file temporarily
    with open("temp_logs.csv", "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # Show preview
    st.subheader("📊 Preview of Uploaded Logs")
    df = pd.read_csv("temp_logs.csv")
    st.dataframe(df, use_container_width=True)
    
    # Run detection
    if st.button("🔍 Analyze for Attacks", use_container_width=True):
        st.info("🔄 Analyzing logs...")
        
        attacks = detect_attacks("temp_logs.csv")
        
        if attacks:
            st.success(f"⚠️ {len(attacks)} ATTACK(S) DETECTED!", icon="🚨")
            
            for attack in attacks:
                with st.expander(f"🚨 Attack on User: {attack['user']} | Risk: {attack['risk_score']*100:.0f}%", expanded=True):
                    
                    # Risk Score
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Risk Score", f"{attack['risk_score']*100:.0f}%")
                    
                    # Timeline
                    st.markdown("---")
                    st.subheader("📅 Attack Timeline")
                    
                    for stage in attack['stages']:
                        with st.container(border=True):
                            col1, col2 = st.columns([1, 3])
                            
                            with col1:
                                st.write(f"### Stage {stage['stage']}")
                            with col2:
                                st.write(f"⏰ **{stage['timestamp']}**")
                            
                            st.write(f"**{stage['description']}**")
                            st.write(f"🔍 *Evidence:* {stage['evidence']}")
                    
                    # Recommendations
                    st.markdown("---")
                    st.subheader("🛡️ Recommendations")
                    for rec in attack['recommendations']:
                        st.error(rec)
        
        else:
            st.success("✅ No attacks detected! Logs are clean.", icon="✅")

else:
    st.info("👈 Upload a CSV file in the sidebar to analyze")
    
    st.markdown("---")
    st.subheader("📝 Example: What This Detects")
    
    example_col1, example_col2, example_col3 = st.columns(3)
    
    with example_col1:
        st.write("**Stage 1**")
        st.write("Unusual login from foreign IP")
    
    with example_col2:
        st.write("**Stage 2**")
        st.write("Access to sensitive files")
    
    with example_col3:
        st.write("**Stage 3**")
        st.write("Copy files to USB drive")
    
    st.success("🚨 = ATTACK DETECTED", icon="✅")