#!/usr/bin/env python3
"""
Report Generation Module
Generates comprehensive HTML and PDF reports from scan results
"""

import base64
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates comprehensive security reports
    """
    
    def __init__(self, config):
        """
        Initialize report generator
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        
        # OWASP Top 10 2021 categories
        self.owasp_top10 = {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures", 
            "A03:2021": "Injection",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable and Outdated Components",
            "A07:2021": "Identification and Authentication Failures",
            "A08:2021": "Software and Data Integrity Failures",
            "A09:2021": "Security Logging and Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery"
        }
        
        # Severity colors for HTML report
        self.severity_colors = {
            'critical': '#dc3545',  # Red
            'high': '#fd7e14',      # Orange  
            'medium': '#ffc107',    # Yellow
            'low': '#17a2b8',       # Blue
            'info': '#6c757d'       # Gray
        }
    
    async def generate_html_report(self, results: Dict) -> str:
        """
        Generate comprehensive HTML report
        
        Args:
            results: Complete scan results
            
        Returns:
            HTML report content
        """
        logger.info("Generating HTML report...")
        
        # Process results for reporting
        processed_results = self._process_results_for_report(results)
        
        # Generate HTML content
        html_content = self._generate_html_content(processed_results)
        
        logger.info("HTML report generated successfully")
        return html_content
    
    def _process_results_for_report(self, results: Dict) -> Dict:
        """
        Process and categorize results for reporting
        
        Args:
            results: Raw scan results
            
        Returns:
            Processed results for reporting
        """
        processed = {
            'scan_info': {
                'target': results.get('target', 'Unknown'),
                'start_time': self._get_formatted_time(),
                'total_urls_crawled': len(results.get('crawled_urls', [])),
                'total_vulnerabilities': 0,
                'risk_level': results.get('summary', {}).get('risk_level', 'Unknown')
            },
            'vulnerabilities_by_category': {},
            'vulnerabilities_by_severity': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            },
            'findings_summary': {
                'sql_injection': {
                    'count': 0,
                    'findings': []
                },
                'xss': {
                    'count': 0,
                    'findings': []
                },
                'path_enumeration': {
                    'count': 0,
                    'findings': []
                },
                'header_analysis': {
                    'count': 0,
                    'findings': []
                }
            },
            'detailed_findings': []
        }
        
        # Process SQL injection results
        sql_findings = results.get('sql_injection', [])
        for finding in sql_findings:
            if finding.get('vulnerable', False):
                processed_finding = self._process_sql_finding(finding)
                processed['detailed_findings'].append(processed_finding)
                processed['findings_summary']['sql_injection']['findings'].append(processed_finding)
                self._categorize_finding(processed_finding, processed)
        
        processed['findings_summary']['sql_injection']['count'] = len(
            processed['findings_summary']['sql_injection']['findings']
        )
        
        # Process XSS results
        xss_findings = results.get('xss', [])
        for finding in xss_findings:
            if finding.get('vulnerable', False):
                processed_finding = self._process_xss_finding(finding)
                processed['detailed_findings'].append(processed_finding)
                processed['findings_summary']['xss']['findings'].append(processed_finding)
                self._categorize_finding(processed_finding, processed)
        
        processed['findings_summary']['xss']['count'] = len(
            processed['findings_summary']['xss']['findings']
        )
        
        # Process path enumeration results
        path_findings = results.get('path_enumeration', [])
        high_risk_paths = [p for p in path_findings if p.get('risk_level') in ['high', 'medium']]
        
        for finding in high_risk_paths:
            processed_finding = self._process_path_finding(finding)
            processed['detailed_findings'].append(processed_finding)
            processed['findings_summary']['path_enumeration']['findings'].append(processed_finding)
            self._categorize_finding(processed_finding, processed)
        
        processed['findings_summary']['path_enumeration']['count'] = len(high_risk_paths)
        
        # Process header analysis results
        header_analysis = results.get('header_analysis', {})
        header_issues = header_analysis.get('issues', [])
        
        for issue in header_issues:
            processed_finding = self._process_header_finding(issue)
            processed['detailed_findings'].append(processed_finding)
            processed['findings_summary']['header_analysis']['findings'].append(processed_finding)
            self._categorize_finding(processed_finding, processed)
        
        processed['findings_summary']['header_analysis']['count'] = len(header_issues)
        
        # Calculate totals
        processed['scan_info']['total_vulnerabilities'] = len(processed['detailed_findings'])
        
        return processed
    
    # --- Corrected Version ---

    def _process_sql_finding(self, finding: Dict) -> Dict:
        """Process SQL injection finding for reporting"""
        return {
            'type': 'SQL Injection',
            'url': finding.get('url', ''),
            'severity': finding.get('severity', 'medium'),
            'owasp_category': "A03:2021", # FIX: Use the standard ID only
            'description': f"SQL injection vulnerability detected on {finding.get('url', 'unknown URL')}",
            'vulnerable_parameters': finding.get('vulnerable_parameters', []),
            'payloads': finding.get('payloads', []),
            'impact': 'Potential database compromise, data theft, or system takeover',
            'recommendation': 'Use parameterized queries, input validation, and principle of least privilege',
            'technical_details': finding,
            'timestamp': finding.get('timestamp', '')
        }

    def _process_xss_finding(self, finding: Dict) -> Dict:
        """Process XSS finding for reporting"""
        return {
            'type': 'Cross-Site Scripting (XSS)',
            'url': finding.get('url', ''),
            'severity': finding.get('severity', 'medium'),
            'owasp_category': "A03:2021", # FIX: Use the standard ID only
            'description': f"XSS vulnerability detected on {finding.get('url', 'unknown URL')}",
            'vulnerable_parameters': finding.get('vulnerable_parameters', []),
            'payloads': finding.get('payloads', []),
            'contexts': finding.get('contexts', []),
            'impact': 'Session hijacking, credential theft, or malicious script execution',
            'recommendation': 'Implement proper input validation, output encoding, and Content Security Policy',
            'technical_details': finding,
            'timestamp': finding.get('timestamp', '')
        }

    def _process_path_finding(self, finding: Dict) -> Dict:
        """Process path enumeration finding for reporting"""
        return {
            'type': 'Sensitive Path Exposure',
            'url': finding.get('url', ''),
            'path': finding.get('path', ''),
            'severity': finding.get('risk_level', 'low'),
            'owasp_category': "A05:2021", # FIX: Use the standard ID only
            'description': finding.get('description', f"Sensitive path discovered: {finding.get('path', '')}"),
            'status_code': finding.get('status_code', 0),
            'indicators': finding.get('indicators', []),
            'impact': 'Information disclosure or unauthorized access to sensitive resources',
            'recommendation': 'Remove or properly secure sensitive paths and directories',
            'technical_details': finding,
            'timestamp': finding.get('timestamp', '')
        }

    def _process_header_finding(self, finding: Dict) -> Dict:
        """Process header analysis finding for reporting"""
        return {
            'type': 'Security Header Issue',
            'url': finding.get('url', ''),
            'header': finding.get('header', ''),
            'severity': finding.get('severity', 'low'),
            'owasp_category': "A05:2021", # FIX: Use the standard ID only
            'description': finding.get('description', 'Security header misconfiguration'),
            'name': finding.get('name', ''),
            'recommendation': finding.get('recommendation', 'Review and implement proper security headers'),
            'impact': 'Reduced protection against various web attacks',
            'technical_details': finding,
            'timestamp': self._get_formatted_time()
        }
    
    def _categorize_finding(self, finding: Dict, processed: Dict):
        """Categorize finding by OWASP category and severity"""
        # By OWASP category
        category = finding.get('owasp_category', 'Other')
        if category not in processed['vulnerabilities_by_category']:
            processed['vulnerabilities_by_category'][category] = []
        processed['vulnerabilities_by_category'][category].append(finding)
        
        # By severity
        severity = finding.get('severity', 'info').lower()
        if severity in processed['vulnerabilities_by_severity']:
            processed['vulnerabilities_by_severity'][severity].append(finding)
    
    def _generate_html_content(self, results: Dict) -> str:
        """
        Generate complete HTML report content
        
        Args:
            results: Processed results
            
        Returns:
            Complete HTML content
        """
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Security Scan Report - {results['scan_info']['target']}</title>
    {self._get_html_styles()}
</head>
<body>
    <div class="container">
        {self._generate_report_header(results)}
        {self._generate_executive_summary(results)}
        {self._generate_vulnerability_overview(results)}
        {self._generate_findings_by_category(results)}
        {self._generate_detailed_findings(results)}
        {self._generate_recommendations(results)}
        {self._generate_appendix(results)}
    </div>
    {self._get_html_scripts()}
</body>
</html>
"""
        return html_template
    
    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        line-height: 1.6;
        color: #333;
        background-color: #f8f9fa;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }
    
    .header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 40px 30px;
        border-radius: 10px;
        margin-bottom: 30px;
        text-align: center;
    }
    
    .header h1 {
        font-size: 2.5em;
        margin-bottom: 10px;
    }
    
    .header .target {
        font-size: 1.2em;
        opacity: 0.9;
    }
    
    .section {
        background: white;
        margin-bottom: 30px;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        overflow: hidden;
    }
    
    .section-header {
        background-color: #f8f9fa;
        padding: 20px 30px;
        border-bottom: 1px solid #dee2e6;
    }
    
    .section-header h2 {
        color: #495057;
        font-size: 1.5em;
    }
    
    .section-content {
        padding: 30px;
    }
    
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin-bottom: 20px;
    }
    
    .summary-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
    }
    
    .summary-card h3 {
        font-size: 2em;
        margin-bottom: 5px;
    }
    
    .summary-card p {
        opacity: 0.9;
    }
    
    .severity-critical { background: linear-gradient(135deg, #ff6b6b 0%, #d63031 100%); }
    .severity-high { background: linear-gradient(135deg, #fd7e14 0%, #e17055 100%); }
    .severity-medium { background: linear-gradient(135deg, #fdcb6e 0%, #e17055 100%); }
    .severity-low { background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%); }
    .severity-info { background: linear-gradient(135deg, #b2bec3 0%, #636e72 100%); }
    
    .vulnerability-item {
        border: 1px solid #dee2e6;
        border-radius: 8px;
        margin-bottom: 20px;
        overflow: hidden;
    }
    
    .vulnerability-header {
        padding: 15px 20px;
        background-color: #f8f9fa;
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
    }
    
    .vulnerability-title {
        font-weight: bold;
        color: #495057;
    }
    
    .severity-badge {
        padding: 4px 12px;
        border-radius: 20px;
        color: white;
        font-size: 0.9em;
        font-weight: bold;
    }
    
    .vulnerability-details {
        padding: 20px;
        display: none;
    }
    
    .vulnerability-details.show {
        display: block;
    }
    
    .detail-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        margin-bottom: 20px;
    }
    
    .detail-item h4 {
        color: #6c757d;
        margin-bottom: 8px;
        font-size: 0.9em;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .code-block {
        background-color: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 4px;
        padding: 15px;
        font-family: monospace;
        overflow-x: auto;
        margin: 10px 0;
    }
    
    .recommendation-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-left: 4px solid #28a745;
        padding: 15px;
        border-radius: 4px;
        margin: 15px 0;
    }
    
    .chart-container {
        height: 400px;
        margin: 20px 0;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
    }
    
    th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #dee2e6;
    }
    
    th {
        background-color: #f8f9fa;
        font-weight: 600;
        color: #495057;
    }
    
    .footer {
        text-align: center;
        padding: 20px;
        color: #6c757d;
        font-size: 0.9em;
    }
    
    @media (max-width: 768px) {
        .container {
            padding: 10px;
        }
        
        .detail-grid {
            grid-template-columns: 1fr;
        }
        
        .summary-grid {
            grid-template-columns: 1fr;
        }
    }
    
    @media print {
        body {
            background-color: white;
        }
        
        .section {
            box-shadow: none;
            border: 1px solid #ccc;
            break-inside: avoid;
        }
    }
</style>
"""
    
    def _generate_report_header(self, results: Dict) -> str:
        """Generate report header section"""
        scan_info = results['scan_info']
        return f"""
<div class="header">
    <h1>🛡️ OWASP Security Scan Report</h1>
    <div class="target">{scan_info['target']}</div>
    <div style="margin-top: 20px; font-size: 0.9em;">
        Generated on {scan_info['start_time']} | 
        Risk Level: <strong>{scan_info['risk_level'].upper()}</strong>
    </div>
</div>
"""
    
    def _generate_executive_summary(self, results: Dict) -> str:
        """Generate executive summary section"""
        scan_info = results['scan_info']
        severity_counts = {k: len(v) for k, v in results['vulnerabilities_by_severity'].items()}
        
        return f"""
<div class="section">
    <div class="section-header">
        <h2>📊 Executive Summary</h2>
    </div>
    <div class="section-content">
        <div class="summary-grid">
            <div class="summary-card">
                <h3>{scan_info['total_urls_crawled']}</h3>
                <p>URLs Crawled</p>
            </div>
            <div class="summary-card severity-critical">
                <h3>{severity_counts['critical']}</h3>
                <p>Critical Issues</p>
            </div>
            <div class="summary-card severity-high">
                <h3>{severity_counts['high']}</h3>
                <p>High Risk Issues</p>
            </div>
            <div class="summary-card severity-medium">
                <h3>{severity_counts['medium']}</h3>
                <p>Medium Risk Issues</p>
            </div>
            <div class="summary-card severity-low">
                <h3>{severity_counts['low'] + severity_counts['info']}</h3>
                <p>Low/Info Issues</p>
            </div>
        </div>
        
        <div class="recommendation-box">
            <h4>🎯 Priority Actions</h4>
            <ul>
                <li>Address all Critical and High severity vulnerabilities immediately</li>
                <li>Implement proper input validation and output encoding</li>
                <li>Configure security headers according to best practices</li>
                <li>Remove or secure sensitive exposed paths</li>
            </ul>
        </div>
    </div>
</div>
"""
    
    def _generate_vulnerability_overview(self, results: Dict) -> str:
        """Generate vulnerability overview with charts"""
        findings_summary = results['findings_summary']
        
        return f"""
<div class="section">
    <div class="section-header">
        <h2>🔍 Vulnerability Overview</h2>
    </div>
    <div class="section-content">
        <table>
            <thead>
                <tr>
                    <th>Vulnerability Type</th>
                    <th>Count</th>
                    <th>OWASP Category</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>SQL Injection</td>
                    <td><span class="severity-badge severity-critical">{findings_summary['sql_injection']['count']}</span></td>
                    <td>A03:2021 – Injection</td>
                    <td>{'❌ Found' if findings_summary['sql_injection']['count'] > 0 else '✅ None Found'}</td>
                </tr>
                <tr>
                    <td>Cross-Site Scripting (XSS)</td>
                    <td><span class="severity-badge severity-high">{findings_summary['xss']['count']}</span></td>
                    <td>A03:2021 – Injection</td>
                    <td>{'❌ Found' if findings_summary['xss']['count'] > 0 else '✅ None Found'}</td>
                </tr>
                <tr>
                    <td>Sensitive Path Exposure</td>
                    <td><span class="severity-badge severity-medium">{findings_summary['path_enumeration']['count']}</span></td>
                    <td>A05:2021 – Security Misconfiguration</td>
                    <td>{'⚠️ Found' if findings_summary['path_enumeration']['count'] > 0 else '✅ None Found'}</td>
                </tr>
                <tr>
                    <td>Security Header Issues</td>
                    <td><span class="severity-badge severity-low">{findings_summary['header_analysis']['count']}</span></td>
                    <td>A05:2021 – Security Misconfiguration</td>
                    <td>{'⚠️ Found' if findings_summary['header_analysis']['count'] > 0 else '✅ None Found'}</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>
"""
    
    def _generate_findings_by_category(self, results: Dict) -> str:
        """Generate findings grouped by OWASP category"""
        categories_html = ""
        
        for category, findings in results['vulnerabilities_by_category'].items():
            if not findings:
                continue
                
            category_name = self.owasp_top10.get(category, category)
            severity_counts = {}
            
            for finding in findings:
                sev = finding.get('severity', 'info')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            categories_html += f"""
            <div class="vulnerability-item">
                <div class="vulnerability-header" onclick="toggleDetails(this)">
                    <div class="vulnerability-title">
                        <strong>{category}</strong> - {category_name} ({len(findings)} findings)
                    </div>
                    <div>
                        {' '.join([f'<span class="severity-badge severity-{sev}">{count}</span>' 
                                  for sev, count in severity_counts.items()])}
                    </div>
                </div>
                <div class="vulnerability-details">
                    <ul>
                        {self._generate_category_finding_list(findings)}
                    </ul>
                </div>
            </div>
            """
        
        return f"""
<div class="section">
    <div class="section-header">
        <h2>📋 Findings by OWASP Category</h2>
    </div>
    <div class="section-content">
        {categories_html}
    </div>
</div>
"""
    
    def _generate_category_finding_list(self, findings: List[Dict]) -> str:
        """Generate list items for findings in a category"""
        items = []
        for finding in findings:
            url = finding.get('url', 'N/A')
            vuln_type = finding.get('type', 'Unknown')
            severity = finding.get('severity', 'info')
            
            items.append(f"""
                <li>
                    <strong>{vuln_type}</strong> on <code>{url}</code>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </li>
            """)
        
        return ''.join(items)
    
    def _generate_detailed_findings(self, results: Dict) -> str:
        """Generate detailed findings section"""
        findings_html = ""
        
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            results['detailed_findings'],
            key=lambda x: severity_order.get(x.get('severity', 'info'), 4)
        )
        
        for i, finding in enumerate(sorted_findings):
            findings_html += self._generate_finding_detail(finding, i)
        
        return f"""
<div class="section">
    <div class="section-header">
        <h2>🔬 Detailed Findings</h2>
    </div>
    <div class="section-content">
        {findings_html}
    </div>
</div>
"""
    
    def _generate_finding_detail(self, finding: Dict, index: int) -> str:
        """Generate detailed view for a single finding"""
        severity = finding.get('severity', 'info')
        vuln_type = finding.get('type', 'Unknown')
        url = finding.get('url', 'N/A')
        description = finding.get('description', 'No description available')
        impact = finding.get('impact', 'No impact assessment available')
        recommendation = finding.get('recommendation', 'No recommendation available')
        
        # Generate technical details
        technical_details = ""
        if finding.get('vulnerable_parameters'):
            technical_details += f"<div class='detail-item'><h4>Vulnerable Parameters</h4><div class='code-block'>{', '.join(finding['vulnerable_parameters'])}</div></div>"
        
        if finding.get('payloads'):
            payloads_text = json.dumps(finding['payloads'], indent=2) if finding['payloads'] else "None"
            technical_details += f"<div class='detail-item'><h4>Payloads</h4><div class='code-block'>{payloads_text}</div></div>"
        
        return f"""
<div class="vulnerability-item">
    <div class="vulnerability-header" onclick="toggleDetails(this)">
        <div class="vulnerability-title">
            #{index + 1} - {vuln_type} - {url}
        </div>
        <span class="severity-badge severity-{severity}">{severity.upper()}</span>
    </div>
    <div class="vulnerability-details">
        <div class="detail-grid">
            <div class="detail-item">
                <h4>Description</h4>
                <p>{description}</p>
            </div>
            <div class="detail-item">
                <h4>OWASP Category</h4>
                <p>{finding.get('owasp_category', 'N/A')}</p>
            </div>
        </div>
        
        <div class="detail-item">
            <h4>Impact</h4>
            <p>{impact}</p>
        </div>
        
        <div class="recommendation-box">
            <h4>💡 Recommendation</h4>
            <p>{recommendation}</p>
        </div>
        
        {technical_details}
    </div>
</div>
"""
    
    def _generate_recommendations(self, results: Dict) -> str:
        """Generate recommendations section"""
        return """
<div class="section">
    <div class="section-header">
        <h2>🛠️ General Recommendations</h2>
    </div>
    <div class="section-content">
        <div class="recommendation-box">
            <h4>🔒 Immediate Actions (Critical/High Priority)</h4>
            <ul>
                <li><strong>SQL Injection:</strong> Implement parameterized queries and input validation</li>
                <li><strong>XSS:</strong> Apply proper output encoding and implement Content Security Policy</li>
                <li><strong>Access Control:</strong> Review and restrict access to sensitive paths</li>
                <li><strong>Security Headers:</strong> Implement comprehensive security headers</li>
            </ul>
        </div>
        
        <div class="recommendation-box">
            <h4>🔧 Implementation Guidelines</h4>
            <ul>
                <li><strong>Input Validation:</strong> Validate all user inputs on both client and server side</li>
                <li><strong>Output Encoding:</strong> Encode data before displaying it to users</li>
                <li><strong>Security Headers:</strong> Configure HSTS, CSP, X-Frame-Options, and other security headers</li>
                <li><strong>Access Controls:</strong> Implement proper authentication and authorization mechanisms</li>
                <li><strong>Regular Testing:</strong> Perform regular security assessments and penetration testing</li>
                <li><strong>Security Training:</strong> Train development team on secure coding practices</li>
            </ul>
        </div>
        
        <div class="recommendation-box">
            <h4>🔄 Long-term Security Strategy</h4>
            <ul>
                <li>Implement a Security Development Lifecycle (SDL)</li>
                <li>Regular security code reviews</li>
                <li>Automated security testing in CI/CD pipeline</li>
                <li>Security monitoring and logging</li>
                <li>Keep dependencies and frameworks updated</li>
                <li>Regular security assessments and penetration testing</li>
            </ul>
        </div>
    </div>
</div>
"""
    
    def _generate_appendix(self, results: Dict) -> str:
        """Generate appendix with technical details"""
        return f"""
<div class="section">
    <div class="section-header">
        <h2>📎 Appendix</h2>
    </div>
    <div class="section-content">
        <h3>Scan Configuration</h3>
        <div class="code-block">
Target: {results['scan_info']['target']}
Scan Date: {results['scan_info']['start_time']}
URLs Crawled: {results['scan_info']['total_urls_crawled']}
Total Findings: {results['scan_info']['total_vulnerabilities']}
        </div>
        
        <h3>OWASP Top 10 2021 Reference</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Name</th>
                    <th>Findings in This Scan</th>
                </tr>
            </thead>
            <tbody>
                {self._generate_owasp_reference_table(results)}
            </tbody>
        </table>
        
        <div class="footer">
            <p>This report was generated by the OWASP Top 10 Security Scanner</p>
            <p>For questions or support, please refer to the documentation</p>
            <p><small>Generated on {self._get_formatted_time()}</small></p>
        </div>
    </div>
</div>
"""
    
    def _generate_owasp_reference_table(self, results: Dict) -> str:
        """Generate OWASP reference table"""
        rows = []
        for category_id, category_name in self.owasp_top10.items():
            findings_count = len(results['vulnerabilities_by_category'].get(category_id, []))
            status = f"✅ {findings_count}" if findings_count > 0 else "➖ 0"
            
            rows.append(f"""
                <tr>
                    <td><strong>{category_id}</strong></td>
                    <td>{category_name}</td>
                    <td>{status}</td>
                </tr>
            """)
        
        return ''.join(rows)
    
    def _get_html_scripts(self) -> str:
        """Get JavaScript for HTML report"""
        return """
<script>
function toggleDetails(element) {
    const details = element.nextElementSibling;
    const isVisible = details.classList.contains('show');
    
    // Close all other details
    document.querySelectorAll('.vulnerability-details.show').forEach(el => {
        el.classList.remove('show');
    });
    
    // Toggle current details
    if (!isVisible) {
        details.classList.add('show');
    }
}

// Print functionality
function printReport() {
    window.print();
}

// Export functionality  
function exportReport() {
    const content = document.documentElement.outerHTML;
    const blob = new Blob([content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security-report.html';
    a.click();
    URL.revokeObjectURL(url);
}

// Add export buttons
document.addEventListener('DOMContentLoaded', function() {
    const header = document.querySelector('.header');
    const buttonContainer = document.createElement('div');
    buttonContainer.style.marginTop = '20px';
    
    const printBtn = document.createElement('button');
    printBtn.textContent = '🖨️ Print Report';
    printBtn.style.cssText = 'padding: 10px 20px; margin: 0 10px; background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 5px; cursor: pointer;';
    printBtn.onclick = printReport;
    
    const exportBtn = document.createElement('button');
    exportBtn.textContent = '💾 Export HTML';
    exportBtn.style.cssText = 'padding: 10px 20px; margin: 0 10px; background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.3); border-radius: 5px; cursor: pointer;';
    exportBtn.onclick = exportReport;
    
    buttonContainer.appendChild(printBtn);
    buttonContainer.appendChild(exportBtn);
    header.appendChild(buttonContainer);
});
</script>
"""
    
    def _get_formatted_time(self) -> str:
        """Get formatted timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    async def generate_pdf_report(self, html_content: str, output_path: str) -> bool:
        """
        Generate PDF report from HTML content
        
        Args:
            html_content: HTML report content
            output_path: Path to save PDF file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Try using weasyprint first
            try:
                import weasyprint
                
                # Create PDF
                html_doc = weasyprint.HTML(string=html_content)
                html_doc.write_pdf(output_path)
                
                logger.info(f"PDF report generated successfully: {output_path}")
                return True
                
            except ImportError:
                logger.warning("WeasyPrint not available, trying wkhtmltopdf...")
                
                # Fallback to wkhtmltopdf
                import tempfile
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as temp_file:
                    temp_file.write(html_content)
                    temp_html_path = temp_file.name
                
                try:
                    import subprocess
                    
                    cmd = [
                        'wkhtmltopdf',
                        '--page-size', 'A4',
                        '--orientation', 'Portrait',
                        '--margin-top', '0.75in',
                        '--margin-right', '0.75in',
                        '--margin-bottom', '0.75in',
                        '--margin-left', '0.75in',
                        '--encoding', 'UTF-8',
                        '--no-outline',
                        temp_html_path,
                        output_path
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"PDF report generated successfully: {output_path}")
                        return True
                    else:
                        logger.error(f"wkhtmltopdf failed: {result.stderr}")
                        
                except FileNotFoundError:
                    logger.error("wkhtmltopdf not found")
                
                finally:
                    # Clean up temp file
                    Path(temp_html_path).unlink(missing_ok=True)
        
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
        
        return False
    
    def generate_json_report(self, results: Dict) -> str:
        """
        Generate JSON report
        
        Args:
            results: Complete scan results
            
        Returns:
            JSON report content
        """
        logger.info("Generating JSON report...")
        
        # Create a clean JSON structure
        json_report = {
            "scan_metadata": {
                "target": results.get('target', ''),
                "timestamp": self._get_formatted_time(),
                "scanner_version": "1.0.0",
                "scan_duration": "N/A"  # Could be calculated if start/end times are tracked
            },
            "summary": {
                "total_urls_crawled": len(results.get('crawled_urls', [])),
                "total_vulnerabilities": len([
                    v for category in [
                        results.get('sql_injection', []),
                        results.get('xss', []),
                        results.get('path_enumeration', []),
                        results.get('header_analysis', {}).get('issues', [])
                    ]
                    for v in category
                    if (isinstance(v, dict) and v.get('vulnerable', False)) or 
                       (not isinstance(v, dict))
                ]),
                "risk_level": results.get('summary', {}).get('risk_level', 'Unknown')
            },
            "vulnerabilities": {
                "sql_injection": results.get('sql_injection', []),
                "xss": results.get('xss', []),
                "path_enumeration": results.get('path_enumeration', []),
                "header_analysis": results.get('header_analysis', {})
            },
            "raw_data": {
                "crawled_urls": results.get('crawled_urls', []),
                "filtered_urls": results.get('filtered_urls', {})
            }
        }
        
        logger.info("JSON report generated successfully")
        return json.dumps(json_report, indent=2, default=str)
    
    def generate_csv_summary(self, results: Dict) -> str:
        """
        Generate CSV summary of findings
        
        Args:
            results: Complete scan results
            
        Returns:
            CSV content
        """
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Vulnerability Type', 'URL', 'Severity', 'OWASP Category',
            'Parameters', 'Status', 'Timestamp'
        ])
        
        # Process each vulnerability type
        vulnerability_types = [
            ('SQL Injection', results.get('sql_injection', [])),
            ('XSS', results.get('xss', [])),
            ('Path Enumeration', results.get('path_enumeration', [])),
        ]
        
        for vuln_type, findings in vulnerability_types:
            for finding in findings:
                if isinstance(finding, dict):
                    if vuln_type in ['SQL Injection', 'XSS'] and not finding.get('vulnerable', False):
                        continue
                    
                    writer.writerow([
                        vuln_type,
                        finding.get('url', 'N/A'),
                        finding.get('severity', finding.get('risk_level', 'info')),
                        finding.get('owasp_category', 'N/A'),
                        ', '.join(finding.get('vulnerable_parameters', [])) or 'N/A',
                        'Vulnerable' if finding.get('vulnerable', True) else 'Safe',
                        finding.get('timestamp', 'N/A')
                    ])
        
        # Add header analysis issues
        header_issues = results.get('header_analysis', {}).get('issues', [])
        for issue in header_issues:
            writer.writerow([
                'Security Header Issue',
                results.get('target', 'N/A'),
                issue.get('severity', 'info'),
                issue.get('owasp_category', 'N/A'),
                issue.get('header', 'N/A'),
                'Issue Found',
                self._get_formatted_time()
            ])
        
        return output.getvalue()