import streamlit as st
import time
from analyzers.binary_analyzer import BinaryAnalyzer
from analyzers.vulnerability_detector import VulnerabilityDetector
from analyzers.security_features import SecurityFeaturesAnalyzer
from analyzers.anti_debug_detector import AntiDebugDetector
from utils.file_handler import FileHandler

st.set_page_config(
    page_title="Upload & Analysis",
    page_icon="📁",
    layout="wide"
)

def main():
    st.title("📁 Binary Upload & Analysis")
    st.markdown("Upload your binary file for comprehensive security analysis")
    
    # Initialize handlers
    file_handler = FileHandler()
    binary_analyzer = BinaryAnalyzer()
    vuln_detector = VulnerabilityDetector()
    security_analyzer = SecurityFeaturesAnalyzer()
    antidebug_detector = AntiDebugDetector()
    
    # File upload section
    st.subheader("📤 Upload Binary File")
    
    uploaded_file = st.file_uploader(
        "Choose a binary file",
        type=None,  # Allow all file types
        help="Supported formats: ELF, PE, Mach-O binaries (.exe, .dll, .so, .bin, .out, etc.)"
    )
    
    if uploaded_file is not None:
        # Display file information
        st.success(f"File uploaded: {uploaded_file.name}")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("File Size", f"{uploaded_file.size:,} bytes")
        with col2:
            st.metric("Size (Human)", file_handler._format_size(uploaded_file.size))
        with col3:
            if file_handler.is_supported_format(uploaded_file.name):
                st.metric("Format Support", "✅ Supported")
            else:
                st.metric("Format Support", "⚠️ May work")
        
        # Analysis button
        if st.button("🔍 Start Analysis", type="primary", use_container_width=True):
            # Save uploaded file
            with st.spinner("Preparing file for analysis..."):
                temp_file_path = file_handler.save_uploaded_file(uploaded_file)
            
            if temp_file_path:
                # Validate file
                validation = file_handler.validate_file(temp_file_path)
                
                if not validation['valid']:
                    st.error(f"❌ File validation failed: {validation['reason']}")
                    file_handler.cleanup_file(temp_file_path)
                    return
                
                st.success(f"✅ File validated as {validation['format']} binary")
                
                # Create progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    # Initialize results
                    analysis_results = {}
                    
                    # Step 1: Basic binary analysis
                    status_text.text("🔍 Analyzing binary structure...")
                    progress_bar.progress(10)
                    
                    binary_results = binary_analyzer.analyze_file(temp_file_path)
                    if 'error' not in binary_results:
                        analysis_results['file_info'] = binary_results
                        st.info(f"📊 Detected: {binary_results.get('file_format', 'Unknown')} - {binary_results.get('architecture', 'Unknown')}")
                    
                    progress_bar.progress(25)
                    
                    # Step 2: Extract strings for analysis
                    status_text.text("🔤 Extracting strings...")
                    strings = binary_results.get('strings', [])
                    progress_bar.progress(40)
                    
                    # Step 3: Vulnerability detection
                    status_text.text("🚨 Scanning for vulnerabilities...")
                    vuln_results = vuln_detector.analyze_vulnerabilities(temp_file_path, strings)
                    if 'error' not in vuln_results:
                        analysis_results['vulnerabilities'] = vuln_results
                    
                    progress_bar.progress(60)
                    
                    # Step 4: Security features analysis
                    status_text.text("🛡️ Analyzing security features...")
                    file_format = binary_results.get('file_format', 'Unknown')
                    security_results = security_analyzer.analyze_security_features(temp_file_path, file_format)
                    if 'error' not in security_results:
                        analysis_results['security_features'] = security_results
                    
                    progress_bar.progress(80)
                    
                    # Step 5: Anti-debug detection
                    status_text.text("🕵️ Detecting anti-debug techniques...")
                    antidebug_results = antidebug_detector.detect_antidebug_techniques(temp_file_path, strings)
                    if 'error' not in antidebug_results:
                        analysis_results['anti_debug'] = antidebug_results
                    
                    progress_bar.progress(100)
                    status_text.text("✅ Analysis complete!")
                    
                    # Store results in session state
                    st.session_state.analysis_results = analysis_results
                    st.session_state.uploaded_file = uploaded_file.name
                    st.session_state.analysis_complete = True
                    
                    # Display quick results
                    st.success("🎉 Analysis completed successfully!")
                    
                    # Quick summary
                    st.subheader("📋 Quick Summary")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        vuln_count = len(vuln_results.get('vulnerable_functions', {}).get('critical', [])) + \
                                   len(vuln_results.get('vulnerable_functions', {}).get('high', []))
                        if vuln_count > 0:
                            st.error(f"🚨 {vuln_count} High/Critical Vulnerabilities")
                        else:
                            st.success("✅ No Critical Vulnerabilities")
                    
                    with col2:
                        security_score = security_results.get('security_score', 0)
                        if security_score >= 70:
                            st.success(f"🛡️ Security Score: {security_score}/100")
                        elif security_score >= 40:
                            st.warning(f"⚠️ Security Score: {security_score}/100")
                        else:
                            st.error(f"🔴 Security Score: {security_score}/100")
                    
                    with col3:
                        evasion_score = antidebug_results.get('evasion_score', 0)
                        if evasion_score >= 50:
                            st.warning(f"🕵️ Evasion Score: {evasion_score}/100")
                        else:
                            st.info(f"👁️ Evasion Score: {evasion_score}/100")
                    
                    with col4:
                        file_format = binary_results.get('file_format', 'Unknown')
                        st.info(f"📄 Format: {file_format}")
                    
                    # Navigation suggestions
                    st.markdown("---")
                    st.subheader("🎯 Next Steps")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.info("📊 **View Dashboard** - Interactive charts and visualizations")
                        st.page_link("pages/2_Dashboard.py", label="Go to Dashboard", icon="📊")
                    
                    with col2:
                        st.info("📋 **Detailed Report** - Comprehensive analysis results")
                        st.page_link("pages/3_Detailed_Report.py", label="View Detailed Report", icon="📋")
                    
                    # Cleanup
                    time.sleep(1)  # Brief pause to show completion
                    
                except Exception as e:
                    st.error(f"❌ Analysis failed: {str(e)}")
                    st.exception(e)
                
                finally:
                    # Clean up temporary file
                    file_handler.cleanup_file(temp_file_path)
                    progress_bar.empty()
                    status_text.empty()
            
            else:
                st.error("❌ Failed to save uploaded file")
    
    else:
        # Show instructions when no file is uploaded
        st.info("👆 Please upload a binary file to begin analysis")
        
        # Display supported formats
        st.subheader("📋 Supported File Formats")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("**🐧 ELF (Linux)**")
            st.markdown("- Executables")
            st.markdown("- Shared libraries (.so)")
            st.markdown("- Object files (.o)")
        
        with col2:
            st.markdown("**🪟 PE (Windows)**")
            st.markdown("- Executables (.exe)")
            st.markdown("- Dynamic libraries (.dll)")
            st.markdown("- Object files (.obj)")
        
        with col3:
            st.markdown("**🍎 Mach-O (macOS)**")
            st.markdown("- Executables")
            st.markdown("- Dynamic libraries (.dylib)")
            st.markdown("- Object files (.o)")
        
        # Features overview
        st.markdown("---")
        st.subheader("🔍 Analysis Features")
        
        features = [
            ("🚨 Vulnerability Detection", "Identifies dangerous functions like gets(), strcpy(), system()"),
            ("🛡️ Security Features", "Checks for ASLR, DEP, stack canaries, PIE, RELRO"),
            ("🕵️ Anti-Debug Detection", "Finds anti-debugging and evasion techniques"),
            ("📊 Binary Analysis", "Extracts metadata, strings, entropy, architecture"),
            ("📈 Risk Assessment", "Provides security scoring and recommendations"),
            ("📋 Detailed Reporting", "Generates comprehensive analysis reports")
        ]
        
        for feature, description in features:
            st.markdown(f"**{feature}**: {description}")
        
        # Tips
        st.markdown("---")
        st.subheader("💡 Tips for Best Results")
        
        st.markdown("""
        - **File Size**: Maximum 100MB per file
        - **Packed Binaries**: Unpack first for better analysis
        - **Stripped Binaries**: Analysis still works but may be less detailed
        - **Multiple Formats**: Upload different variants for comparison
        - **False Positives**: Review findings in context of your use case
        """)

if __name__ == "__main__":
    main()
