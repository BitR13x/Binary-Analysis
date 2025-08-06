import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, Any, List

st.set_page_config(
    page_title="Analysis Dashboard",
    page_icon="📊",
    layout="wide"
)

def main():
    st.title("📊 Analysis Dashboard")
    st.markdown("Interactive visualizations and insights from binary analysis")
    
    # Check if analysis results are available
    if not st.session_state.get('analysis_complete', False) or not st.session_state.get('analysis_results'):
        st.warning("⚠️ No analysis results available. Please upload and analyze a binary first.")
        st.page_link("pages/1_Upload_Analysis.py", label="Go to Upload & Analysis", icon="📁")
        return
    
    results = st.session_state.analysis_results
    filename = st.session_state.get('uploaded_file', 'Unknown')
    
    # Header with file info
    st.markdown(f"### Analysis Results for: `{filename}`")
    st.markdown("---")
    
    # Key Metrics Dashboard
    st.subheader("🎯 Key Security Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Extract key metrics
    vuln_data = results.get('vulnerabilities', {})
    security_data = results.get('security_features', {})
    antidebug_data = results.get('anti_debug', {})
    file_info = results.get('file_info', {})
    
    with col1:
        vuln_score = vuln_data.get('severity_score', 0)
        delta_color = "inverse" if vuln_score > 50 else "normal"
        st.metric("Vulnerability Score", f"{vuln_score}/100", delta=None)
        if vuln_score > 70:
            st.error("🔴 Critical Risk")
        elif vuln_score > 40:
            st.warning("🟠 High Risk")
        elif vuln_score > 20:
            st.info("🟡 Medium Risk")
        else:
            st.success("🟢 Low Risk")
    
    with col2:
        security_score = security_data.get('security_score', 0)
        st.metric("Security Score", f"{security_score}/100", delta=None)
        if security_score >= 80:
            st.success("🛡️ Well Protected")
        elif security_score >= 60:
            st.info("⚡ Moderately Protected")
        elif security_score >= 40:
            st.warning("⚠️ Poorly Protected")
        else:
            st.error("🚨 Minimal Protection")
    
    with col3:
        evasion_score = antidebug_data.get('evasion_score', 0)
        st.metric("Evasion Score", f"{evasion_score}/100", delta=None)
        if evasion_score >= 60:
            st.warning("🕵️ High Evasion")
        elif evasion_score >= 30:
            st.info("👁️ Moderate Evasion")
        else:
            st.success("🔍 Low Evasion")
    
    with col4:
        entropy = file_info.get('entropy', 0)
        st.metric("File Entropy", f"{entropy:.2f}", delta=None)
        if entropy >= 7.5:
            st.warning("📦 Likely Packed")
        elif entropy >= 6.0:
            st.info("🔀 High Entropy")
        else:
            st.success("📄 Normal Entropy")
    
    st.markdown("---")
    
    # Create tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["🚨 Vulnerabilities", "🛡️ Security Features", "🕵️ Anti-Debug", "📊 File Analysis"])
    
    with tab1:
        create_vulnerability_dashboard(vuln_data)
    
    with tab2:
        create_security_features_dashboard(security_data)
    
    with tab3:
        create_antidebug_dashboard(antidebug_data)
    
    with tab4:
        create_file_analysis_dashboard(file_info)

def create_vulnerability_dashboard(vuln_data: Dict[str, Any]):
    """Create vulnerability analysis dashboard"""
    st.subheader("🚨 Vulnerability Analysis Dashboard")
    
    if not vuln_data or 'vulnerable_functions' not in vuln_data:
        st.info("No vulnerability data available")
        return
    
    vulnerable_functions = vuln_data.get('vulnerable_functions', {})
    risk_assessment = vuln_data.get('risk_assessment', {})
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Vulnerability distribution pie chart
        severity_counts = {}
        total_functions = []
        
        for severity, functions in vulnerable_functions.items():
            if functions:
                severity_counts[severity.title()] = len(functions)
                total_functions.extend(functions)
        
        if severity_counts:
            fig_pie = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Vulnerable Functions by Severity",
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14', 
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
            )
            fig_pie.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.success("✅ No vulnerable functions detected!")
    
    with col2:
        # Risk metrics
        st.markdown("#### Risk Assessment")
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        
        risk_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '⚪'
        }
        
        st.markdown(f"**Overall Risk:** {risk_colors.get(risk_level, '❓')} {risk_level}")
        
        risk_factors = risk_assessment.get('risk_factors', {})
        for factor, count in risk_factors.items():
            if count > 0:
                st.markdown(f"**{factor.replace('_', ' ').title()}:** {count}")
    
    # Detailed function breakdown
    if any(vulnerable_functions.values()):
        st.markdown("#### Detected Vulnerable Functions")
        
        # Create bar chart of vulnerable functions
        all_functions = []
        for severity, functions in vulnerable_functions.items():
            for func in functions:
                all_functions.append({'Function': func, 'Severity': severity.title()})
        
        if all_functions:
            df_functions = pd.DataFrame(all_functions)
            function_counts = df_functions['Function'].value_counts()
            
            fig_bar = px.bar(
                x=function_counts.values,
                y=function_counts.index,
                orientation='h',
                title="Most Common Vulnerable Functions",
                labels={'x': 'Count', 'y': 'Function'},
                color=function_counts.values,
                color_continuous_scale='Reds'
            )
            fig_bar.update_layout(height=400)
            st.plotly_chart(fig_bar, use_container_width=True)
            
            # Function details table
            with st.expander("📋 Function Details"):
                for severity, functions in vulnerable_functions.items():
                    if functions:
                        st.markdown(f"**{severity.upper()} Risk Functions:**")
                        for func in functions:
                            st.markdown(f"- `{func}`")
    
    # Recommendations
    recommendations = vuln_data.get('recommendations', [])
    if recommendations:
        st.markdown("#### 💡 Security Recommendations")
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"{i}. {rec}")

def create_security_features_dashboard(security_data: Dict[str, Any]):
    """Create security features dashboard"""
    st.subheader("🛡️ Security Features Dashboard")
    
    if not security_data or 'features' not in security_data:
        st.info("No security features data available")
        return
    
    features = security_data.get('features', {})
    security_score = security_data.get('security_score', 0)
    
    # Security score gauge
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Create gauge chart for security score
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = security_score,
            title = {'text': "Overall Security Score"},
            delta = {'reference': 80},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkgreen"},
                'steps': [
                    {'range': [0, 40], 'color': "lightgray"},
                    {'range': [40, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "green"}],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90}}))
        fig_gauge.update_layout(height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)
    
    with col2:
        # Feature status summary
        enabled_count = 0
        disabled_count = 0
        
        for feature_name, feature_data in features.items():
            if isinstance(feature_data, dict) and 'enabled' in feature_data:
                if feature_data['enabled']:
                    enabled_count += 1
                else:
                    disabled_count += 1
        
        st.markdown("#### Feature Summary")
        st.success(f"✅ Enabled: {enabled_count}")
        st.error(f"❌ Disabled: {disabled_count}")
        
        if enabled_count + disabled_count > 0:
            protection_ratio = (enabled_count / (enabled_count + disabled_count)) * 100
            st.metric("Protection Ratio", f"{protection_ratio:.1f}%")
    
    # Feature details visualization
    if features:
        feature_status = []
        feature_names = []
        
        for feature_name, feature_data in features.items():
            if isinstance(feature_data, dict) and 'enabled' in feature_data:
                feature_names.append(feature_name.replace('_', ' ').title())
                feature_status.append(1 if feature_data['enabled'] else 0)
        
        if feature_names:
            # Create horizontal bar chart
            colors = ['green' if status else 'red' for status in feature_status]
            
            fig_features = go.Figure(go.Bar(
                y=feature_names,
                x=[1] * len(feature_names),  # All bars same length
                orientation='h',
                marker_color=colors,
                text=['✅ Enabled' if status else '❌ Disabled' for status in feature_status],
                textposition='inside'
            ))
            
            fig_features.update_layout(
                title="Security Features Status",
                xaxis={'visible': False},
                height=max(300, len(feature_names) * 30)
            )
            
            st.plotly_chart(fig_features, use_container_width=True)
        
        # Detailed feature information
        with st.expander("🔍 Detailed Feature Analysis"):
            for feature_name, feature_data in features.items():
                if isinstance(feature_data, dict):
                    status_icon = "✅" if feature_data.get('enabled', False) else "❌"
                    st.markdown(f"**{status_icon} {feature_name.replace('_', ' ').title()}**")
                    st.markdown(f"Details: {feature_data.get('details', 'No details available')}")
                    st.markdown("---")
    
    # Recommendations
    recommendations = security_data.get('recommendations', [])
    if recommendations:
        st.markdown("#### 💡 Security Recommendations")
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"{i}. {rec}")

def create_antidebug_dashboard(antidebug_data: Dict[str, Any]):
    """Create anti-debug analysis dashboard"""
    st.subheader("🕵️ Anti-Debug Analysis Dashboard")
    
    if not antidebug_data:
        st.info("No anti-debug data available")
        return
    
    techniques = antidebug_data.get('techniques', [])
    evasion_score = antidebug_data.get('evasion_score', 0)
    severity_assessment = antidebug_data.get('severity_assessment', {})
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Evasion score gauge
        fig_evasion = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = evasion_score,
            title = {'text': "Evasion Score"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "orange"},
                'steps': [
                    {'range': [0, 30], 'color': "lightgray"},
                    {'range': [30, 60], 'color': "yellow"},
                    {'range': [60, 100], 'color': "red"}],
                'threshold': {
                    'line': {'color': "darkred", 'width': 4},
                    'thickness': 0.75,
                    'value': 80}}))
        fig_evasion.update_layout(height=300)
        st.plotly_chart(fig_evasion, use_container_width=True)
    
    with col2:
        # Threat level and breakdown
        threat_level = severity_assessment.get('threat_level', 'UNKNOWN')
        st.markdown("#### Threat Assessment")
        
        threat_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡', 
            'LOW': '🟢',
            'MINIMAL': '⚪'
        }
        
        st.markdown(f"**Threat Level:** {threat_colors.get(threat_level, '❓')} {threat_level}")
        st.markdown(f"**Total Techniques:** {len(techniques)}")
        
        severity_breakdown = severity_assessment.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            if count > 0:
                st.markdown(f"**{severity.title()}:** {count}")
    
    # Techniques analysis
    if techniques:
        # Severity distribution
        severity_counts = {}
        for technique in techniques:
            severity = technique.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            fig_severity = px.pie(
                values=list(severity_counts.values()),
                names=[s.title() for s in severity_counts.keys()],
                title="Anti-Debug Techniques by Severity",
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107', 
                    'Low': '#28a745',
                    'Unknown': '#6c757d'
                }
            )
            st.plotly_chart(fig_severity, use_container_width=True)
        
        # Confidence vs Severity scatter plot
        if len(techniques) > 1:
            technique_data = []
            for technique in techniques:
                confidence_map = {'high': 3, 'medium': 2, 'low': 1}
                severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
                
                technique_data.append({
                    'name': technique.get('name', 'Unknown'),
                    'confidence': confidence_map.get(technique.get('confidence', 'low'), 1),
                    'severity': severity_map.get(technique.get('severity', 'low'), 1),
                    'description': technique.get('description', 'No description')
                })
            
            df_techniques = pd.DataFrame(technique_data)
            
            fig_scatter = px.scatter(
                df_techniques,
                x='confidence',
                y='severity', 
                hover_name='name',
                hover_data=['description'],
                title="Technique Confidence vs Severity",
                labels={'confidence': 'Confidence Level', 'severity': 'Severity Level'},
                color='severity',
                size='severity',
                color_continuous_scale='Reds'
            )
            
            fig_scatter.update_xaxes(tickmode='array', tickvals=[1,2,3], ticktext=['Low','Medium','High'])
            fig_scatter.update_yaxes(tickmode='array', tickvals=[1,2,3,4], ticktext=['Low','Medium','High','Critical'])
            
            st.plotly_chart(fig_scatter, use_container_width=True)
        
        # Detailed techniques table
        with st.expander("🔍 Detected Techniques Details"):
            for technique in techniques:
                name = technique.get('name', 'Unknown')
                severity = technique.get('severity', 'unknown')
                confidence = technique.get('confidence', 'low')
                description = technique.get('description', 'No description available')
                
                severity_color = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(severity, '❓')
                
                st.markdown(f"**{severity_color} {name}** ({severity} severity, {confidence} confidence)")
                st.markdown(f"Description: {description}")
                st.markdown("---")
    
    # VM Detection
    vm_detection = antidebug_data.get('vm_detection', [])
    if vm_detection:
        st.markdown("#### 🖥️ Virtual Machine Detection")
        for vm in vm_detection:
            vm_name = vm.get('vm_name', 'Unknown')
            indicators = vm.get('indicators', [])
            st.warning(f"**{vm_name}** detected (indicators: {', '.join(indicators)})")
    
    # Debugger checks
    debugger_checks = antidebug_data.get('debugger_checks', [])
    if debugger_checks:
        st.markdown("#### 🐛 Debugger Detection")
        st.warning(f"Debugger strings found: {', '.join(debugger_checks)}")
    
    # Recommendations
    recommendations = antidebug_data.get('recommendations', [])
    if recommendations:
        st.markdown("#### 💡 Analysis Recommendations")
        for i, rec in enumerate(recommendations, 1):
            st.markdown(f"{i}. {rec}")

def create_file_analysis_dashboard(file_info: Dict[str, Any]):
    """Create file analysis dashboard"""
    st.subheader("📊 File Analysis Dashboard")
    
    if not file_info:
        st.info("No file analysis data available")
        return
    
    # File metadata
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📄 File Metadata")
        
        metadata_items = [
            ("Filename", file_info.get('filename', 'Unknown')),
            ("Size", file_info.get('size_human', 'Unknown')),
            ("Format", file_info.get('file_format', 'Unknown')),
            ("Architecture", file_info.get('architecture', 'Unknown')),
            ("Entropy", f"{file_info.get('entropy', 0):.4f}")
        ]
        
        for label, value in metadata_items:
            st.markdown(f"**{label}:** {value}")
    
    with col2:
        st.markdown("#### 🔍 File Hashes")
        
        hashes = file_info.get('hashes', {})
        for hash_type, hash_value in hashes.items():
            if hash_value:
                st.code(f"{hash_type.upper()}: {hash_value}")
    
    # Entropy analysis
    entropy = file_info.get('entropy', 0)
    if entropy > 0:
        st.markdown("#### 📈 Entropy Analysis")
        
        # Create entropy visualization
        fig_entropy = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = entropy,
            title = {'text': "File Entropy"},
            gauge = {
                'axis': {'range': [0, 8]},
                'bar': {'color': "blue"},
                'steps': [
                    {'range': [0, 5], 'color': "lightgray"},
                    {'range': [5, 7], 'color': "yellow"},
                    {'range': [7, 8], 'color': "red"}],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 7.5}}))
        
        fig_entropy.update_layout(height=300)
        st.plotly_chart(fig_entropy, use_container_width=True)
        
        # Entropy interpretation
        if entropy >= 7.5:
            st.warning("🚨 High entropy detected - file may be packed or encrypted")
        elif entropy >= 6.0:
            st.info("ℹ️ Moderate entropy - normal for compiled binaries")
        else:
            st.success("✅ Low entropy - typical for uncompressed binaries")
    
    # String analysis
    strings = file_info.get('strings', [])
    if strings:
        st.markdown("#### 🔤 String Analysis")
        
        string_count = len(strings)
        st.metric("Total Strings", string_count)
        
        # String length distribution
        string_lengths = [len(s) for s in strings[:1000]]  # Limit for performance
        if string_lengths:
            fig_strings = px.histogram(
                x=string_lengths,
                title="String Length Distribution",
                labels={'x': 'String Length', 'y': 'Count'},
                nbins=30
            )
            st.plotly_chart(fig_strings, use_container_width=True)
        
        # Sample strings
        with st.expander("📝 Sample Strings"):
            # Show interesting strings first
            interesting_strings = []
            for s in strings[:200]:  # Limit for performance
                if any(keyword in s.lower() for keyword in ['http', 'ftp', 'www', 'exe', 'dll', 'error', 'warning', 'debug']):
                    interesting_strings.append(s)
            
            if interesting_strings:
                st.markdown("**Interesting Strings:**")
                for s in interesting_strings[:20]:
                    st.code(s)
            else:
                st.markdown("**Sample Strings:**")
                for s in strings[:20]:
                    if len(s.strip()) > 3:  # Skip very short strings
                        st.code(s)

if __name__ == "__main__":
    main()
