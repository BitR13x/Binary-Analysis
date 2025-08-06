import streamlit as st
import json
from datetime import datetime
from utils.report_generator import ReportGenerator
from typing import Dict, Any

st.set_page_config(
    page_title="Detailed Report",
    page_icon="📋",
    layout="wide"
)

def main():
    st.title("📋 Detailed Analysis Report")
    st.markdown("Comprehensive security analysis results and export options")
    
    # Check if analysis results are available
    if not st.session_state.get('analysis_complete', False) or not st.session_state.get('analysis_results'):
        st.warning("⚠️ No analysis results available. Please upload and analyze a binary first.")
        st.page_link("pages/1_Upload_Analysis.py", label="Go to Upload & Analysis", icon="📁")
        return
    
    results = st.session_state.analysis_results
    filename = st.session_state.get('uploaded_file', 'Unknown')
    
    # Report header
    st.markdown(f"### Analysis Report for: `{filename}`")
    st.markdown(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.markdown("---")
    
    # Export options
    col1, col2, col3 = st.columns(3)
    
    report_generator = ReportGenerator()
    
    with col1:
        if st.button("📥 Export JSON Report", use_container_width=True):
            json_report = report_generator.create_downloadable_report(results, 'json')
            if json_report:
                st.download_button(
                    label="Download JSON Report",
                    data=json_report,
                    file_name=f"binary_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
    
    with col2:
        if st.button("📄 Export Text Report", use_container_width=True):
            text_report = report_generator.create_downloadable_report(results, 'txt')
            if text_report:
                st.download_button(
                    label="Download Text Report",
                    data=text_report,
                    file_name=f"binary_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
    
    with col3:
        if st.button("🌐 Export HTML Report", use_container_width=True):
            html_report = report_generator.create_downloadable_report(results, 'html')
            if html_report:
                st.download_button(
                    label="Download HTML Report",
                    data=html_report,
                    file_name=f"binary_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html"
                )
    
    st.markdown("---")
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Executive Summary", 
        "📄 File Information", 
        "🚨 Vulnerabilities", 
        "🛡️ Security Features", 
        "🕵️ Anti-Debug Analysis"
    ])
    
    with tab1:
        display_executive_summary(results)
    
    with tab2:
        display_file_information(results.get('file_info', {}))
    
    with tab3:
        display_vulnerability_analysis(results.get('vulnerabilities', {}))
    
    with tab4:
        display_security_features(results.get('security_features', {}))
    
    with tab5:
        display_antidebug_analysis(results.get('anti_debug', {}))

def display_executive_summary(results: Dict[str, Any]):
    """Display executive summary"""
    st.subheader("📊 Executive Summary")
    
    # Calculate key metrics
    vuln_data = results.get('vulnerabilities', {})
    security_data = results.get('security_features', {})
    antidebug_data = results.get('anti_debug', {})
    
    vuln_score = vuln_data.get('severity_score', 0)
    security_score = security_data.get('security_score', 0)
    evasion_score = antidebug_data.get('evasion_score', 0)
    
    # Overall risk assessment
    st.markdown("#### 🎯 Overall Risk Assessment")
    
    if vuln_score > 70 or evasion_score > 80:
        st.error("🔴 **CRITICAL RISK**: This binary poses significant security threats and requires immediate attention.")
    elif vuln_score > 40 or evasion_score > 60 or security_score < 30:
        st.warning("🟠 **HIGH RISK**: Multiple security concerns identified that should be addressed.")
    elif vuln_score > 20 or evasion_score > 30 or security_score < 60:
        st.info("🟡 **MEDIUM RISK**: Some security issues present that warrant investigation.")
    else:
        st.success("🟢 **LOW RISK**: Basic security analysis shows minimal immediate concerns.")
    
    # Key metrics summary
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("##### Vulnerability Analysis")
        st.metric("Severity Score", f"{vuln_score}/100")
        risk_level = vuln_data.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        st.markdown(f"**Risk Level:** {risk_level}")
        
        # Count vulnerabilities by severity
        vuln_funcs = vuln_data.get('vulnerable_functions', {})
        critical_count = len(vuln_funcs.get('critical', []))
        high_count = len(vuln_funcs.get('high', []))
        
        if critical_count > 0:
            st.error(f"🔴 {critical_count} Critical vulnerabilities")
        if high_count > 0:
            st.warning(f"🟠 {high_count} High-risk vulnerabilities")
    
    with col2:
        st.markdown("##### Security Features")
        st.metric("Security Score", f"{security_score}/100")
        
        features = security_data.get('features', {})
        enabled_count = sum(1 for f in features.values() if isinstance(f, dict) and f.get('enabled', False))
        total_count = len([f for f in features.values() if isinstance(f, dict) and 'enabled' in f])
        
        if total_count > 0:
            st.markdown(f"**Enabled Features:** {enabled_count}/{total_count}")
            protection_ratio = (enabled_count / total_count) * 100
            if protection_ratio >= 80:
                st.success(f"🛡️ Well protected ({protection_ratio:.0f}%)")
            elif protection_ratio >= 60:
                st.info(f"⚡ Moderately protected ({protection_ratio:.0f}%)")
            else:
                st.warning(f"⚠️ Poorly protected ({protection_ratio:.0f}%)")
    
    with col3:
        st.markdown("##### Anti-Debug Analysis")
        st.metric("Evasion Score", f"{evasion_score}/100")
        threat_level = antidebug_data.get('severity_assessment', {}).get('threat_level', 'UNKNOWN')
        st.markdown(f"**Threat Level:** {threat_level}")
        
        techniques_count = len(antidebug_data.get('techniques', []))
        if techniques_count > 0:
            st.warning(f"🕵️ {techniques_count} anti-debug techniques detected")
        else:
            st.success("🔍 No anti-debug techniques detected")
    
    # Recommendations summary
    st.markdown("#### 💡 Key Recommendations")
    
    all_recommendations = set()
    for section in [vuln_data, security_data, antidebug_data]:
        if isinstance(section, dict) and 'recommendations' in section:
            all_recommendations.update(section.get('recommendations', [])[:3])  # Top 3 from each
    
    if all_recommendations:
        for i, rec in enumerate(sorted(all_recommendations)[:8], 1):  # Top 8 overall
            st.markdown(f"{i}. {rec}")
    else:
        st.info("No specific recommendations available.")

def display_file_information(file_info: Dict[str, Any]):
    """Display detailed file information"""
    st.subheader("📄 File Information")
    
    if not file_info:
        st.info("No file information available")
        return
    
    # Basic file metadata
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📋 Basic Information")
        
        basic_info = [
            ("Filename", file_info.get('filename', 'Unknown')),
            ("File Size", file_info.get('size_human', 'Unknown')),
            ("File Format", file_info.get('file_format', 'Unknown')),
            ("Architecture", file_info.get('architecture', 'Unknown')),
            ("Entropy", f"{file_info.get('entropy', 0):.4f}")
        ]
        
        for label, value in basic_info:
            st.markdown(f"**{label}:** `{value}`")
        
        # Entropy analysis
        entropy = file_info.get('entropy', 0)
        if entropy >= 7.5:
            st.warning("⚠️ High entropy - possibly packed/encrypted")
        elif entropy >= 6.0:
            st.info("ℹ️ Normal entropy for compiled binary")
        else:
            st.success("✅ Low entropy - typical for uncompressed binary")
    
    with col2:
        st.markdown("#### 🔍 Cryptographic Hashes")
        
        hashes = file_info.get('hashes', {})
        if hashes:
            for hash_type, hash_value in hashes.items():
                if hash_value:
                    st.markdown(f"**{hash_type.upper()}:**")
                    st.code(hash_value)
        else:
            st.info("No hash information available")
    
    # Format-specific analysis
    file_format = file_info.get('file_format', 'Unknown')
    
    if file_format != 'Unknown':
        st.markdown(f"#### 🔧 {file_format} Specific Analysis")
        
        if file_format == 'ELF' and 'elf_header' in file_info:
            with st.expander("ELF Header Information"):
                st.code(file_info['elf_header'])
        
        elif file_format == 'PE' and 'pe_signature' in file_info:
            st.markdown(f"**PE Signature:** {file_info['pe_signature']}")
        
        elif file_format == 'Mach-O' and 'macho_signature' in file_info:
            st.markdown(f"**Mach-O Signature:** {file_info['macho_signature']}")
    
    # String analysis
    strings = file_info.get('strings', [])
    if strings:
        st.markdown("#### 🔤 String Analysis")
        
        string_count = len(strings)
        st.metric("Total Strings Extracted", string_count)
        
        # Categorize strings
        interesting_strings = []
        url_strings = []
        file_strings = []
        error_strings = []
        
        for s in strings[:500]:  # Limit for performance
            s_lower = s.lower()
            if any(proto in s_lower for proto in ['http://', 'https://', 'ftp://']):
                url_strings.append(s)
            elif any(ext in s_lower for ext in ['.exe', '.dll', '.so', '.dylib']):
                file_strings.append(s)
            elif any(word in s_lower for word in ['error', 'fail', 'exception', 'warning']):
                error_strings.append(s)
            elif any(keyword in s_lower for keyword in ['password', 'key', 'secret', 'token', 'api']):
                interesting_strings.append(s)
        
        # Display categorized strings
        if url_strings:
            with st.expander(f"🌐 URL Strings ({len(url_strings)})"):
                for url in url_strings[:20]:
                    st.code(url)
        
        if file_strings:
            with st.expander(f"📁 File References ({len(file_strings)})"):
                for file_ref in file_strings[:20]:
                    st.code(file_ref)
        
        if error_strings:
            with st.expander(f"⚠️ Error Messages ({len(error_strings)})"):
                for error in error_strings[:20]:
                    st.code(error)
        
        if interesting_strings:
            with st.expander(f"🔑 Potentially Sensitive Strings ({len(interesting_strings)})"):
                for sensitive in interesting_strings[:20]:
                    st.code(sensitive)
        
        # Sample of all strings
        with st.expander(f"📝 Sample Strings (showing first 50 of {string_count})"):
            for s in strings[:50]:
                if len(s.strip()) > 3:
                    st.code(s)

def display_vulnerability_analysis(vuln_data: Dict[str, Any]):
    """Display vulnerability analysis details"""
    st.subheader("🚨 Vulnerability Analysis")
    
    if not vuln_data:
        st.info("No vulnerability analysis data available")
        return
    
    # Risk assessment overview
    risk_assessment = vuln_data.get('risk_assessment', {})
    severity_score = vuln_data.get('severity_score', 0)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 Risk Assessment")
        st.metric("Severity Score", f"{severity_score}/100")
        
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        risk_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '⚪'
        }
        
        st.markdown(f"**Overall Risk Level:** {risk_colors.get(risk_level, '❓')} {risk_level}")
        
        total_vulns = risk_assessment.get('total_vulnerabilities', 0)
        st.markdown(f"**Total Vulnerabilities:** {total_vulns}")
    
    with col2:
        st.markdown("#### 📈 Risk Factors")
        risk_factors = risk_assessment.get('risk_factors', {})
        
        for factor, count in risk_factors.items():
            if count > 0:
                factor_name = factor.replace('_', ' ').title()
                if 'critical' in factor.lower():
                    st.error(f"🔴 {factor_name}: {count}")
                elif 'high' in factor.lower():
                    st.warning(f"🟠 {factor_name}: {count}")
                elif 'medium' in factor.lower():
                    st.info(f"🟡 {factor_name}: {count}")
                else:
                    st.success(f"🟢 {factor_name}: {count}")
    
    # Vulnerable functions breakdown
    vulnerable_functions = vuln_data.get('vulnerable_functions', {})
    
    if any(vulnerable_functions.values()):
        st.markdown("#### 🎯 Vulnerable Functions Detected")
        
        for severity in ['critical', 'high', 'medium', 'low']:
            functions = vulnerable_functions.get(severity, [])
            if functions:
                severity_colors = {
                    'critical': 'error',
                    'high': 'warning', 
                    'medium': 'info',
                    'low': 'success'
                }
                
                with st.expander(f"{severity.title()} Risk Functions ({len(functions)})"):
                    st.markdown(f"**{severity.upper()} severity functions found:**")
                    
                    for func in functions:
                        col_func, col_desc = st.columns([1, 2])
                        
                        with col_func:
                            st.code(func)
                        
                        with col_desc:
                            # Get function details (would need to import VulnerabilityDetector)
                            st.markdown(f"Potentially unsafe function that may lead to buffer overflows or other security issues.")
                    
                    # Show usage context if available
                    st.markdown("**Recommended Actions:**")
                    if severity == 'critical':
                        st.markdown("- 🚨 **URGENT**: Replace with safer alternatives immediately")
                        st.markdown("- 🔍 **Review**: All code paths that use these functions")
                        st.markdown("- 🛡️ **Implement**: Input validation and bounds checking")
                    elif severity == 'high':
                        st.markdown("- ⚠️ **High Priority**: Consider replacing with safer alternatives")
                        st.markdown("- 📋 **Audit**: Usage patterns and input sources")
                    elif severity == 'medium':
                        st.markdown("- 📝 **Monitor**: Usage and ensure proper bounds checking")
                        st.markdown("- 🔍 **Validate**: All inputs to these functions")
                    else:
                        st.markdown("- 👁️ **Awareness**: Be mindful of secure usage patterns")
    else:
        st.success("✅ No vulnerable functions detected!")
    
    # Vulnerability patterns
    vuln_patterns = vuln_data.get('vulnerability_patterns', {})
    if vuln_patterns:
        st.markdown("#### 🔍 Vulnerability Patterns")
        
        for pattern_type, matches in vuln_patterns.items():
            if matches:
                with st.expander(f"{pattern_type.replace('_', ' ').title()} ({len(matches)})"):
                    st.markdown(f"**Pattern Type:** {pattern_type}")
                    st.markdown(f"**Matches Found:** {len(matches)}")
                    
                    for match in matches[:10]:  # Show first 10 matches
                        st.code(match)
                    
                    if len(matches) > 10:
                        st.info(f"... and {len(matches) - 10} more matches")
    
    # Recommendations
    recommendations = vuln_data.get('recommendations', [])
    if recommendations:
        st.markdown("#### 💡 Security Recommendations")
        
        for i, rec in enumerate(recommendations, 1):
            if 'URGENT' in rec or '🚨' in rec:
                st.error(f"{i}. {rec}")
            elif 'HIGH' in rec or '⚠️' in rec:
                st.warning(f"{i}. {rec}")
            else:
                st.info(f"{i}. {rec}")

def display_security_features(security_data: Dict[str, Any]):
    """Display security features analysis"""
    st.subheader("🛡️ Security Features Analysis")
    
    if not security_data:
        st.info("No security features data available")
        return
    
    # Security score overview
    security_score = security_data.get('security_score', 0)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 📊 Security Score")
        st.metric("Overall Security Score", f"{security_score}/100")
        
        if security_score >= 80:
            st.success("🛡️ Excellent security posture")
        elif security_score >= 60:
            st.info("⚡ Good security features enabled")
        elif security_score >= 40:
            st.warning("⚠️ Some security features missing")
        else:
            st.error("🚨 Poor security configuration")
    
    with col2:
        # Feature summary
        features = security_data.get('features', {})
        enabled_count = 0
        disabled_count = 0
        
        for feature_data in features.values():
            if isinstance(feature_data, dict) and 'enabled' in feature_data:
                if feature_data['enabled']:
                    enabled_count += 1
                else:
                    disabled_count += 1
        
        st.markdown("#### 📋 Feature Summary")
        st.success(f"✅ Enabled: {enabled_count}")
        st.error(f"❌ Disabled: {disabled_count}")
        
        if enabled_count + disabled_count > 0:
            protection_ratio = (enabled_count / (enabled_count + disabled_count)) * 100
            st.metric("Protection Coverage", f"{protection_ratio:.1f}%")
    
    # Detailed feature analysis
    if features:
        st.markdown("#### 🔍 Detailed Feature Analysis")
        
        for feature_name, feature_data in features.items():
            if isinstance(feature_data, dict):
                enabled = feature_data.get('enabled', False)
                details = feature_data.get('details', 'No details available')
                
                with st.expander(f"{'✅' if enabled else '❌'} {feature_name.replace('_', ' ').title()}"):
                    st.markdown(f"**Status:** {'Enabled' if enabled else 'Disabled'}")
                    st.markdown(f"**Details:** {details}")
                    
                    # Feature-specific information
                    if feature_name == 'stack_canary':
                        if enabled:
                            st.success("🛡️ Stack buffer overflow protection is active")
                            st.markdown("**Benefit:** Helps detect and prevent stack-based buffer overflows")
                        else:
                            st.error("⚠️ No stack canary protection detected")
                            st.markdown("**Risk:** Vulnerable to stack-based buffer overflow attacks")
                            st.markdown("**Recommendation:** Enable stack canaries (-fstack-protector)")
                    
                    elif feature_name == 'nx_bit':
                        if enabled:
                            st.success("🛡️ Non-executable stack/heap protection")
                            st.markdown("**Benefit:** Prevents code execution on stack and heap")
                        else:
                            st.error("⚠️ Stack/heap may be executable")
                            st.markdown("**Risk:** Shellcode execution possible")
                            st.markdown("**Recommendation:** Enable NX bit protection")
                    
                    elif feature_name == 'aslr':
                        if enabled:
                            st.success("🔀 Address Space Layout Randomization active")
                            st.markdown("**Benefit:** Makes memory corruption exploits more difficult")
                        else:
                            st.error("⚠️ Predictable memory layout")
                            st.markdown("**Risk:** Easier exploitation of memory corruption bugs")
                            st.markdown("**Recommendation:** Enable ASLR support")
                    
                    elif feature_name == 'pie':
                        if enabled:
                            st.success("📍 Position Independent Executable")
                            st.markdown("**Benefit:** Executable base address randomization")
                        else:
                            st.warning("⚠️ Fixed base address")
                            st.markdown("**Risk:** Predictable code location")
                            st.markdown("**Recommendation:** Compile with -fPIE")
                    
                    elif feature_name == 'relro':
                        if enabled:
                            st.success("🔒 RELocation Read-Only protection")
                            st.markdown("**Benefit:** Protects GOT/PLT from overwrites")
                        else:
                            st.warning("⚠️ GOT/PLT may be writable")
                            st.markdown("**Risk:** Global Offset Table attacks possible")
                            st.markdown("**Recommendation:** Enable RELRO (-Wl,-z,relro)")
                    
                    # Add additional feature info if present
                    if 'symbols_found' in feature_data:
                        st.markdown(f"**Symbols Found:** {', '.join(feature_data['symbols_found'])}")
                    
                    if 'functions' in feature_data:
                        st.markdown(f"**Functions:** {', '.join(feature_data['functions'])}")
    
    # Recommendations
    recommendations = security_data.get('recommendations', [])
    if recommendations:
        st.markdown("#### 💡 Security Recommendations")
        
        for i, rec in enumerate(recommendations, 1):
            st.info(f"{i}. {rec}")

def display_antidebug_analysis(antidebug_data: Dict[str, Any]):
    """Display anti-debug analysis details"""
    st.subheader("🕵️ Anti-Debug Analysis")
    
    if not antidebug_data:
        st.info("No anti-debug analysis data available")
        return
    
    # Threat assessment overview
    severity_assessment = antidebug_data.get('severity_assessment', {})
    evasion_score = antidebug_data.get('evasion_score', 0)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ⚠️ Threat Assessment")
        
        threat_level = severity_assessment.get('threat_level', 'UNKNOWN')
        threat_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'MINIMAL': '⚪'
        }
        
        st.markdown(f"**Threat Level:** {threat_colors.get(threat_level, '❓')} {threat_level}")
        st.metric("Evasion Score", f"{evasion_score}/100")
        
        total_techniques = severity_assessment.get('total_techniques', 0)
        st.markdown(f"**Techniques Detected:** {total_techniques}")
    
    with col2:
        st.markdown("#### 📊 Severity Breakdown")
        
        severity_breakdown = severity_assessment.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            if count > 0:
                severity_colors = {
                    'critical': '🔴',
                    'high': '🟠', 
                    'medium': '🟡',
                    'low': '🟢'
                }
                color = severity_colors.get(severity, '❓')
                st.markdown(f"**{color} {severity.title()}:** {count}")
    
    # Detected techniques
    techniques = antidebug_data.get('techniques', [])
    
    if techniques:
        st.markdown("#### 🎯 Detected Anti-Debug Techniques")
        
        for technique in techniques:
            name = technique.get('name', 'Unknown')
            description = technique.get('description', 'No description available')
            severity = technique.get('severity', 'unknown')
            confidence = technique.get('confidence', 'low')
            matches = technique.get('matches', [])
            
            severity_colors = {
                'critical': 'error',
                'high': 'warning',
                'medium': 'info', 
                'low': 'success'
            }
            
            severity_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            with st.expander(f"{severity_icons.get(severity, '❓')} {name} ({severity} severity, {confidence} confidence)"):
                st.markdown(f"**Description:** {description}")
                st.markdown(f"**Severity:** {severity.title()}")
                st.markdown(f"**Detection Confidence:** {confidence.title()}")
                
                if matches:
                    st.markdown("**Evidence Found:**")
                    for match in matches[:10]:  # Show first 10 matches
                        st.code(match)
                    
                    if len(matches) > 10:
                        st.info(f"... and {len(matches) - 10} more matches")
                
                # Technique-specific guidance
                if name == 'ptrace':
                    st.markdown("**Analysis Impact:** This technique can prevent debugger attachment")
                    st.markdown("**Bypass Methods:** Use LD_PRELOAD to hook ptrace, or patch the binary")
                elif name == 'timing_checks':
                    st.markdown("**Analysis Impact:** May detect slow execution during debugging")
                    st.markdown("**Bypass Methods:** Use timing attack mitigation in debugger")
                elif name == 'debugger_detection':
                    st.markdown("**Analysis Impact:** Directly checks for debugger presence")
                    st.markdown("**Bypass Methods:** Use stealthy debuggers or patch detection routines")
                elif name == 'vm_detection':
                    st.markdown("**Analysis Impact:** May detect virtual machine environment")
                    st.markdown("**Bypass Methods:** Use bare-metal analysis or patch VM checks")
    else:
        st.success("✅ No anti-debug techniques detected!")
    
    # VM Detection
    vm_detection = antidebug_data.get('vm_detection', [])
    if vm_detection:
        st.markdown("#### 🖥️ Virtual Machine Detection")
        
        for vm in vm_detection:
            vm_name = vm.get('vm_name', 'Unknown')
            indicators = vm.get('indicators', [])
            
            with st.expander(f"🖥️ {vm_name} Detection"):
                st.warning(f"**Virtual Machine Detected:** {vm_name}")
                st.markdown(f"**Indicators Found:** {', '.join(indicators)}")
                st.markdown("**Impact:** Binary may behave differently in VM environment")
                st.markdown("**Recommendation:** Consider bare-metal analysis for accurate results")
    
    # Debugger Checks
    debugger_checks = antidebug_data.get('debugger_checks', [])
    if debugger_checks:
        st.markdown("#### 🐛 Debugger String Detection")
        
        st.warning(f"**Debugger-related strings found:** {', '.join(debugger_checks)}")
        st.markdown("**Impact:** Binary may specifically check for these debugging tools")
        st.markdown("**Recommendation:** Use alternative tools or rename/hide debugger processes")
    
    # Timing Attacks
    timing_attacks = antidebug_data.get('timing_attacks', [])
    if timing_attacks:
        st.markdown("#### ⏱️ Timing Attack Detection")
        
        st.warning(f"**Timing functions found:** {', '.join(timing_attacks)}")
        st.markdown("**Impact:** Binary may measure execution time to detect debugging")
        st.markdown("**Recommendation:** Use timing attack resistant debugging methods")
    
    # API Obfuscation
    api_obfuscation = antidebug_data.get('api_obfuscation', {})
    if api_obfuscation:
        st.markdown("#### 🔧 API Obfuscation Detection")
        
        for category, functions in api_obfuscation.items():
            if functions:
                with st.expander(f"{category.replace('_', ' ').title()} ({len(functions)})"):
                    st.markdown(f"**Category:** {category}")
                    st.markdown(f"**Functions Found:** {', '.join(functions)}")
                    
                    if category == 'dynamic_loading':
                        st.markdown("**Impact:** APIs may be loaded dynamically to evade static analysis")
                    elif category == 'string_obfuscation':
                        st.markdown("**Impact:** Strings may be obfuscated or encrypted")
                    elif category == 'api_hashing':
                        st.markdown("**Impact:** API names may be resolved via hash lookups")
    
    # Packing Indicators
    packing_indicators = antidebug_data.get('packing_indicators', {})
    if packing_indicators:
        st.markdown("#### 📦 Packing/Obfuscation Detection")
        
        for category, indicators in packing_indicators.items():
            if indicators:
                with st.expander(f"{category.replace('_', ' ').title()} ({len(indicators)})"):
                    st.markdown(f"**Category:** {category}")
                    st.markdown(f"**Indicators:** {', '.join(indicators)}")
                    
                    if category == 'packing':
                        st.warning("**Impact:** Binary may be packed, making analysis difficult")
                        st.markdown("**Recommendation:** Unpack the binary before detailed analysis")
                    elif category == 'obfuscation':
                        st.warning("**Impact:** Code may be obfuscated")
                        st.markdown("**Recommendation:** Use deobfuscation tools")
                    elif category == 'encryption':
                        st.warning("**Impact:** Parts of the binary may be encrypted")
                        st.markdown("**Recommendation:** Look for decryption routines")
    
    # Recommendations
    recommendations = antidebug_data.get('recommendations', [])
    if recommendations:
        st.markdown("#### 💡 Analysis Recommendations")
        
        for i, rec in enumerate(recommendations, 1):
            if 'URGENT' in rec or '🚨' in rec:
                st.error(f"{i}. {rec}")
            elif 'advanced' in rec.lower() or 'specialized' in rec.lower():
                st.warning(f"{i}. {rec}")
            else:
                st.info(f"{i}. {rec}")

if __name__ == "__main__":
    main()
