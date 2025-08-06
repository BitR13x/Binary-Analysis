import json
import datetime
from typing import Dict, Any, Optional
import streamlit as st
import tempfile
import os

class ReportGenerator:
    def __init__(self):
        self.report_formats = ['json', 'txt', 'html']
    
    def generate_report(self, analysis_results: Dict[str, Any], format_type: str = 'json') -> Optional[str]:
        """Generate analysis report in specified format"""
        try:
            if format_type == 'json':
                return self._generate_json_report(analysis_results)
            elif format_type == 'txt':
                return self._generate_text_report(analysis_results)
            elif format_type == 'html':
                return self._generate_html_report(analysis_results)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
        except Exception as e:
            st.error(f"Report generation failed: {str(e)}")
            return None
    
    def _generate_json_report(self, results: Dict[str, Any]) -> str:
        """Generate JSON format report"""
        report = {
            'metadata': {
                'tool': 'Binary Analysis Automation Tool',
                'version': '1.0.0',
                'timestamp': datetime.datetime.now().isoformat(),
                'analysis_type': 'comprehensive_binary_analysis'
            },
            'file_info': results.get('file_info', {}),
            'binary_analysis': results.get('binary_analysis', {}),
            'vulnerabilities': results.get('vulnerabilities', {}),
            'security_features': results.get('security_features', {}),
            'anti_debug': results.get('anti_debug', {}),
            'summary': self._generate_summary(results)
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _generate_text_report(self, results: Dict[str, Any]) -> str:
        """Generate plain text report"""
        report_lines = []
        
        # Header
        report_lines.extend([
            "=" * 80,
            "BINARY ANALYSIS AUTOMATION TOOL - SECURITY REPORT",
            "=" * 80,
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ])
        
        # File Information
        file_info = results.get('file_info', {})
        if file_info:
            report_lines.extend([
                "FILE INFORMATION",
                "-" * 40,
                f"Filename: {file_info.get('filename', 'Unknown')}",
                f"Size: {file_info.get('size_human', 'Unknown')}",
                f"Format: {file_info.get('file_format', 'Unknown')}",
                f"Architecture: {file_info.get('architecture', 'Unknown')}",
                f"MD5: {file_info.get('hashes', {}).get('md5', 'Unknown')}",
                f"SHA256: {file_info.get('hashes', {}).get('sha256', 'Unknown')}",
                "",
            ])
        
        # Vulnerability Analysis
        vulnerabilities = results.get('vulnerabilities', {})
        if vulnerabilities:
            report_lines.extend([
                "VULNERABILITY ANALYSIS",
                "-" * 40,
                f"Severity Score: {vulnerabilities.get('severity_score', 0)}/100",
                f"Risk Level: {vulnerabilities.get('risk_assessment', {}).get('risk_level', 'Unknown')}",
                "",
            ])
            
            # Vulnerable functions
            vuln_funcs = vulnerabilities.get('vulnerable_functions', {})
            for severity, functions in vuln_funcs.items():
                if functions:
                    report_lines.append(f"{severity.upper()} Risk Functions: {', '.join(functions)}")
            
            report_lines.append("")
        
        # Security Features
        security = results.get('security_features', {})
        if security:
            report_lines.extend([
                "SECURITY FEATURES",
                "-" * 40,
                f"Security Score: {security.get('security_score', 0)}/100",
                "",
                "Feature Status:",
            ])
            
            features = security.get('features', {})
            for feature_name, feature_data in features.items():
                if isinstance(feature_data, dict):
                    status = "✅ ENABLED" if feature_data.get('enabled', False) else "❌ DISABLED"
                    report_lines.append(f"  {feature_name}: {status}")
            
            report_lines.append("")
        
        # Anti-Debug Analysis
        anti_debug = results.get('anti_debug', {})
        if anti_debug:
            report_lines.extend([
                "ANTI-DEBUG ANALYSIS",
                "-" * 40,
                f"Evasion Score: {anti_debug.get('evasion_score', 0)}/100",
                f"Threat Level: {anti_debug.get('severity_assessment', {}).get('threat_level', 'Unknown')}",
                "",
            ])
            
            techniques = anti_debug.get('techniques', [])
            if techniques:
                report_lines.append("Detected Techniques:")
                for technique in techniques:
                    name = technique.get('name', 'Unknown')
                    severity = technique.get('severity', 'unknown')
                    confidence = technique.get('confidence', 'low')
                    report_lines.append(f"  - {name} ({severity} severity, {confidence} confidence)")
            
            report_lines.append("")
        
        # Recommendations
        all_recommendations = set()
        for section in [vulnerabilities, security, anti_debug]:
            if isinstance(section, dict) and 'recommendations' in section:
                all_recommendations.update(section['recommendations'])
        
        if all_recommendations:
            report_lines.extend([
                "RECOMMENDATIONS",
                "-" * 40,
            ])
            for i, rec in enumerate(sorted(all_recommendations), 1):
                report_lines.append(f"{i}. {rec}")
            
            report_lines.append("")
        
        # Summary
        summary = self._generate_summary(results)
        if summary:
            report_lines.extend([
                "EXECUTIVE SUMMARY",
                "-" * 40,
                summary.get('overall_risk', 'Risk assessment unavailable'),
                "",
                f"Total Issues Found: {summary.get('total_issues', 0)}",
                f"Critical Issues: {summary.get('critical_issues', 0)}",
                f"High Priority Issues: {summary.get('high_issues', 0)}",
                "",
            ])
        
        report_lines.extend([
            "=" * 80,
            "End of Report",
            "=" * 80
        ])
        
        return "\n".join(report_lines)
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML format report"""
        summary = self._generate_summary(results)
        
        # Get data for report
        file_info = results.get('file_info', {})
        vulnerabilities = results.get('vulnerabilities', {})
        security = results.get('security_features', {})
        anti_debug = results.get('anti_debug', {})
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Binary Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background: #f4f4f4; padding: 20px; border-left: 5px solid #333; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .score {{ font-size: 2em; font-weight: bold; }}
        .enabled {{ color: #28a745; }}
        .disabled {{ color: #dc3545; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .recommendations {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Binary Analysis Security Report</h1>
        <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Tool: Binary Analysis Automation Tool v1.0.0</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="score {summary.get('risk_class', 'medium')}">{summary.get('overall_risk', 'Assessment unavailable')}</div>
        <p><strong>Total Issues:</strong> {summary.get('total_issues', 0)}</p>
        <p><strong>Critical Issues:</strong> {summary.get('critical_issues', 0)}</p>
        <p><strong>Security Score:</strong> {security.get('security_score', 0)}/100</p>
    </div>
    
    <div class="section">
        <h2>File Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Filename</td><td>{file_info.get('filename', 'Unknown')}</td></tr>
            <tr><td>Size</td><td>{file_info.get('size_human', 'Unknown')}</td></tr>
            <tr><td>Format</td><td>{file_info.get('file_format', 'Unknown')}</td></tr>
            <tr><td>Architecture</td><td>{file_info.get('architecture', 'Unknown')}</td></tr>
            <tr><td>MD5</td><td>{file_info.get('hashes', {}).get('md5', 'Unknown')}</td></tr>
            <tr><td>SHA256</td><td>{file_info.get('hashes', {}).get('sha256', 'Unknown')}</td></tr>
        </table>
    </div>
    
    <div class="section {self._get_risk_class(vulnerabilities.get('severity_score', 0))}">
        <h2>Vulnerability Analysis</h2>
        <p><strong>Severity Score:</strong> <span class="score">{vulnerabilities.get('severity_score', 0)}/100</span></p>
        <p><strong>Risk Level:</strong> {vulnerabilities.get('risk_assessment', {}).get('risk_level', 'Unknown')}</p>
        
        <h3>Vulnerable Functions</h3>
        <table>
            <tr><th>Severity</th><th>Functions</th></tr>
        """
        
        # Add vulnerable functions table
        vuln_funcs = vulnerabilities.get('vulnerable_functions', {})
        for severity, functions in vuln_funcs.items():
            if functions:
                html += f"<tr><td class='{severity}'>{severity.upper()}</td><td>{', '.join(functions)}</td></tr>"
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Security Features</h2>
        <p><strong>Security Score:</strong> <span class="score">{}/100</span></p>
        <table>
            <tr><th>Feature</th><th>Status</th><th>Details</th></tr>
        """.format(security.get('security_score', 0))
        
        # Add security features table
        features = security.get('features', {})
        for feature_name, feature_data in features.items():
            if isinstance(feature_data, dict):
                status = '<span class="enabled">✅ ENABLED</span>' if feature_data.get('enabled', False) else '<span class="disabled">❌ DISABLED</span>'
                details = feature_data.get('details', 'No details available')
                html += f"<tr><td>{feature_name}</td><td>{status}</td><td>{details}</td></tr>"
        
        html += """
        </table>
    </div>
    
    <div class="section">
        <h2>Anti-Debug Analysis</h2>
        <p><strong>Evasion Score:</strong> <span class="score">{}/100</span></p>
        <p><strong>Threat Level:</strong> {}</p>
        
        <h3>Detected Techniques</h3>
        <table>
            <tr><th>Technique</th><th>Severity</th><th>Confidence</th><th>Description</th></tr>
        """.format(
            anti_debug.get('evasion_score', 0),
            anti_debug.get('severity_assessment', {}).get('threat_level', 'Unknown')
        )
        
        # Add anti-debug techniques table
        techniques = anti_debug.get('techniques', [])
        for technique in techniques:
            name = technique.get('name', 'Unknown')
            severity = technique.get('severity', 'unknown')
            confidence = technique.get('confidence', 'low')
            description = technique.get('description', 'No description available')
            html += f"<tr><td>{name}</td><td class='{severity}'>{severity.upper()}</td><td>{confidence}</td><td>{description}</td></tr>"
        
        # Collect all recommendations
        all_recommendations = set()
        for section in [vulnerabilities, security, anti_debug]:
            if isinstance(section, dict) and 'recommendations' in section:
                all_recommendations.update(section['recommendations'])
        
        html += """
        </table>
    </div>
    
    <div class="section recommendations">
        <h2>Recommendations</h2>
        <ol>
        """
        
        for rec in sorted(all_recommendations):
            html += f"<li>{rec}</li>"
        
        html += """
        </ol>
    </div>
    
    <div class="section">
        <p><em>This report was generated by the Binary Analysis Automation Tool. For questions or support, please refer to the tool documentation.</em></p>
    </div>
    
</body>
</html>
"""
        
        return html
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        try:
            vulnerabilities = results.get('vulnerabilities', {})
            security = results.get('security_features', {})
            anti_debug = results.get('anti_debug', {})
            
            # Calculate issue counts
            vuln_score = vulnerabilities.get('severity_score', 0)
            security_score = security.get('security_score', 0)
            evasion_score = anti_debug.get('evasion_score', 0)
            
            # Determine overall risk
            if vuln_score > 70 or evasion_score > 80:
                overall_risk = "CRITICAL RISK: This binary poses significant security threats"
                risk_class = "critical"
            elif vuln_score > 40 or evasion_score > 60 or security_score < 30:
                overall_risk = "HIGH RISK: Multiple security concerns identified"
                risk_class = "high"
            elif vuln_score > 20 or evasion_score > 30 or security_score < 60:
                overall_risk = "MEDIUM RISK: Some security issues present"
                risk_class = "medium"
            else:
                overall_risk = "LOW RISK: Basic security analysis complete"
                risk_class = "low"
            
            # Count issues
            vuln_funcs = vulnerabilities.get('vulnerable_functions', {})
            critical_issues = len(vuln_funcs.get('critical', []))
            high_issues = len(vuln_funcs.get('high', []))
            total_issues = sum(len(funcs) for funcs in vuln_funcs.values())
            
            return {
                'overall_risk': overall_risk,
                'risk_class': risk_class,
                'total_issues': total_issues,
                'critical_issues': critical_issues,
                'high_issues': high_issues,
                'vulnerability_score': vuln_score,
                'security_score': security_score,
                'evasion_score': evasion_score
            }
            
        except Exception as e:
            return {
                'overall_risk': f"Summary generation failed: {str(e)}",
                'risk_class': 'medium',
                'total_issues': 0,
                'critical_issues': 0,
                'high_issues': 0
            }
    
    def _get_risk_class(self, score: int) -> str:
        """Get CSS class based on risk score"""
        if score > 70:
            return 'critical'
        elif score > 40:
            return 'high'
        elif score > 20:
            return 'medium'
        else:
            return 'low'
    
    def create_downloadable_report(self, analysis_results: Dict[str, Any], format_type: str) -> Optional[str]:
        """Create a downloadable report file"""
        try:
            report_content = self.generate_report(analysis_results, format_type)
            if not report_content:
                return None
            
            # Generate filename with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"binary_analysis_report_{timestamp}.{format_type}"
            
            # For Streamlit, we'll return the content directly
            # The calling code can use st.download_button
            return report_content
            
        except Exception as e:
            st.error(f"Failed to create downloadable report: {str(e)}")
            return None
