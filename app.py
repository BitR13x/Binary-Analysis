import streamlit as st
import os
from pathlib import Path

# Configure page
st.set_page_config(
    page_title="Binary Analysis Automation Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'uploaded_file' not in st.session_state:
    st.session_state.uploaded_file = None
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False

def main():
    st.title("🔍 Binary Analysis Automation Tool")
    st.markdown("### CTF Professional Security Analysis Dashboard")
    
    st.markdown("""
    Welcome to the Binary Analysis Automation Tool designed for busy CTF professionals. 
    This tool provides comprehensive binary analysis including:
    
    - **Vulnerability Detection**: Identifies dangerous functions and potential security issues
    - **Anti-Debug Detection**: Discovers anti-debugging and anti-analysis techniques
    - **Security Features**: Analyzes binary protections (ASLR, DEP, Stack Canaries, PIE)
    - **Binary Information**: Extracts metadata, architecture, and entropy analysis
    - **Interactive Dashboard**: Visual representation of analysis results
    """)
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    st.sidebar.markdown("---")
    
    if st.session_state.analysis_complete:
        st.sidebar.success("✅ Analysis Complete")
        st.sidebar.markdown("Navigate to:")
        st.sidebar.markdown("- 📊 **Dashboard** for visual overview")
        st.sidebar.markdown("- 📋 **Detailed Report** for comprehensive results")
    else:
        st.sidebar.info("👆 Start by uploading a binary file")
    
    # Quick stats if analysis is complete
    if st.session_state.analysis_complete and st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        st.markdown("---")
        st.subheader("📊 Quick Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            vuln_count = len(results.get('vulnerabilities', {}).get('vulnerable_functions', []))
            st.metric("Vulnerabilities Found", vuln_count, delta=None)
        
        with col2:
            antidebug_count = len(results.get('anti_debug', {}).get('techniques', []))
            st.metric("Anti-Debug Techniques", antidebug_count, delta=None)
        
        with col3:
            security_score = results.get('security_features', {}).get('security_score', 0)
            st.metric("Security Score", f"{security_score}/100", delta=None)
        
        with col4:
            file_info = results.get('file_info', {})
            file_type = file_info.get('file_format', 'Unknown')
            st.metric("File Format", file_type, delta=None)
        
        # Risk assessment
        st.markdown("---")
        st.subheader("🎯 Risk Assessment")
        
        if vuln_count > 5:
            st.error("🔴 High Risk - Multiple vulnerabilities detected")
        elif vuln_count > 2:
            st.warning("🟡 Medium Risk - Some vulnerabilities found")
        elif vuln_count > 0:
            st.info("🟠 Low Risk - Few vulnerabilities detected")
        else:
            st.success("🟢 Low Risk - No obvious vulnerabilities found")
    
    # Instructions
    st.markdown("---")
    st.subheader("🚀 Getting Started")
    st.markdown("""
    1. **Upload Binary**: Go to the Upload & Analysis page to upload your binary file
    2. **Wait for Analysis**: The tool will automatically analyze the binary for security issues
    3. **View Results**: Navigate to the Dashboard for visual insights or Detailed Report for comprehensive analysis
    4. **Export Report**: Download your analysis results in multiple formats
    """)
    
    # Supported formats
    st.markdown("---")
    st.subheader("📁 Supported Formats")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**ELF Binaries**")
        st.markdown("- Linux executables")
        st.markdown("- Shared libraries (.so)")
        st.markdown("- Object files (.o)")
    
    with col2:
        st.markdown("**PE Binaries**")
        st.markdown("- Windows executables (.exe)")
        st.markdown("- Dynamic libraries (.dll)")
        st.markdown("- Object files (.obj)")
    
    with col3:
        st.markdown("**Mach-O Binaries**")
        st.markdown("- macOS executables")
        st.markdown("- Dynamic libraries (.dylib)")
        st.markdown("- Object files (.o)")

if __name__ == "__main__":
    main()
