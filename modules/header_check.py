#!/usr/bin/env python3
"""
Header Analysis Module
Analyzes security headers using nikto and securityheaders.com API
"""

import asyncio
import json
import logging
import random
import re
import subprocess
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from .utils import RateLimiter

logger = logging.getLogger(__name__)


class HeaderAnalyzer:
    """
    Security header analysis using multiple methods
    """
    
    def __init__(self, config):
        """
        Initialize header analyzer
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.rate_limiter = RateLimiter(requests_per_second=0.5)  # Be gentle with external APIs
        
        # OWASP Top 10 mapping
        self.owasp_category = "A05:2021 – Security Misconfiguration"
        
        # Security headers to check
        self.security_headers = {
            'strict-transport-security': {
                'name': 'HTTP Strict Transport Security (HSTS)',
                'description': 'Enforces secure HTTPS connections',
                'severity': 'medium',
                'required': True
            },
            'content-security-policy': {
                'name': 'Content Security Policy (CSP)',
                'description': 'Controls resource loading to prevent XSS',
                'severity': 'high',
                'required': True
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'description': 'Prevents page embedding in frames (clickjacking protection)',
                'severity': 'medium',
                'required': True
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'description': 'Prevents MIME type sniffing',
                'severity': 'low',
                'required': True
            },
            'referrer-policy': {
                'name': 'Referrer Policy',
                'description': 'Controls referrer information in requests',
                'severity': 'low',
                'required': False
            },
            'permissions-policy': {
                'name': 'Permissions Policy',
                'description': 'Controls browser feature access',
                'severity': 'low',
                'required': False
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'description': 'Legacy XSS protection (deprecated but still useful)',
                'severity': 'low',
                'required': False
            }
        }
        
        # Dangerous headers that should not be present
        self.dangerous_headers = {
            'server': {
                'name': 'Server Header',
                'description': 'Reveals server software and version',
                'severity': 'info'
            },
            'x-powered-by': {
                'name': 'X-Powered-By',
                'description': 'Reveals technology stack',
                'severity': 'info'
            },
            'x-aspnet-version': {
                'name': 'X-AspNet-Version',
                'description': 'Reveals ASP.NET version',
                'severity': 'low'
            },
            'x-aspnetmvc-version': {
                'name': 'X-AspNetMvc-Version',
                'description': 'Reveals ASP.NET MVC version',
                'severity': 'low'
            }
        }
    
    async def analyze_headers(self, target: str, progress=None, task_id=None) -> Dict:
        """
        Analyze security headers using multiple methods
        
        Args:
            target: Target URL
            progress: Optional progress tracker
            task_id: Optional task ID for progress updates
            
        Returns:
            Header analysis results
        """
        logger.info(f"Starting header analysis on {target}")
        
        result = {
            'target': target,
            'headers': {},
            'issues': [],
            'score': 0,
            'grade': 'F',
            'timestamp': self._get_timestamp(),
            'analysis_methods': []
        }
        
        try:
            # Update progress
            if progress and task_id:
                progress.update(task_id, description="Analyzing headers...")
            
            # Method 1: Direct header fetch
            if progress and task_id:
                progress.update(task_id, description="Fetching headers directly...")
            
            direct_result = await self._fetch_headers_direct(target)
            if direct_result:
                result['headers'].update(direct_result['headers'])
                result['analysis_methods'].append('direct_fetch')
            
            # Method 2: SecurityHeaders.com API (if enabled)
            if self.config.get('headers.use_api', True):
                if progress and task_id:
                    progress.update(task_id, description="Using SecurityHeaders.com API...")
                
                api_result = await self._analyze_with_api(target)
                if api_result:
                    result.update(api_result)
                    result['analysis_methods'].append('securityheaders_api')
            
            # Method 3: Nikto (if available)
            try:
                if progress and task_id:
                    progress.update(task_id, description="Running nikto analysis...")
                
                nikto_result = await self._run_nikto(target)
                if nikto_result:
                    result['nikto_findings'] = nikto_result
                    result['analysis_methods'].append('nikto')
            except Exception as e:
                logger.debug(f"Nikto analysis failed: {str(e)}")
            
            # Analyze collected headers
            analysis_result = self._analyze_collected_headers(result['headers'])
            result['issues'].extend(analysis_result['issues'])
            result['score'] = analysis_result['score']
            result['grade'] = analysis_result['grade']
            
        except Exception as e:
            logger.error(f"Header analysis failed: {str(e)}")
            result['error'] = str(e)
        
        logger.info(f"Header analysis completed. Grade: {result['grade']}, Issues: {len(result['issues'])}")
        return result
    
    async def _fetch_headers_direct(self, target: str) -> Optional[Dict]:
        """
        Fetch headers directly using curl
        
        Args:
            target: Target URL
            
        Returns:
            Headers and metadata
        """
        try:
            user_agent = random.choice(self.config.get('general.user_agents', ['Security-Scanner']))
            
            cmd = [
                'curl', '-s', '-I', '-L',
                '--max-time', str(self.config.get('headers.timeout', 10)),
                '--user-agent', user_agent,
                target
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                headers = self._parse_http_headers(stdout.decode())
                return {
                    'headers': headers,
                    'method': 'direct_fetch'
                }
            
        except Exception as e:
            logger.debug(f"Direct header fetch failed: {str(e)}")
        
        return None
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """
        Parse HTTP headers from curl response
        
        Args:
            response: HTTP response text
            
        Returns:
            Dictionary of headers
        """
        headers = {}
        
        lines = response.strip().split('\n')
        for line in lines:
            line = line.strip()
            
            # Skip status line and empty lines
            if line.startswith('HTTP/') or not line:
                continue
            
            # Parse header
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return headers
    
    async def _analyze_with_api(self, target: str) -> Optional[Dict]:
        """
        Analyze headers using SecurityHeaders.com API
        
        Args:
            target: Target URL
            
        Returns:
            API analysis results
        """
        try:
            await self.rate_limiter.wait_if_needed()
            
            # Extract domain from URL
            parsed_url = urlparse(target)
            domain = parsed_url.netloc
            
            # SecurityHeaders.com API endpoint
            api_url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
            
            # Make API request
            cmd = [
                'curl', '-s', '-H', 'Accept: application/json',
                '--max-time', str(self.config.get('headers.api_timeout', 15)),
                api_url
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Try to parse JSON response
                try:
                    data = json.loads(stdout.decode())
                    return self._parse_api_response(data)
                except json.JSONDecodeError:
                    # If not JSON, try to parse HTML response
                    return self._parse_api_html_response(stdout.decode())
            
        except Exception as e:
            logger.debug(f"SecurityHeaders.com API failed: {str(e)}")
        
        return None
    
    def _parse_api_response(self, data: Dict) -> Dict:
        """
        Parse SecurityHeaders.com API JSON response
        
        Args:
            data: API response data
            
        Returns:
            Parsed results
        """
        result = {
            'headers': {},
            'score': data.get('score', 0),
            'grade': data.get('grade', 'F'),
            'api_analysis': True
        }
        
        # Parse header information
        if 'headers' in data:
            for header_name, header_info in data['headers'].items():
                result['headers'][header_name.lower()] = header_info.get('value', '')
        
        return result
    
    def _parse_api_html_response(self, html: str) -> Dict:
        """
        Parse SecurityHeaders.com HTML response (fallback)
        
        Args:
            html: HTML response
            
        Returns:
            Parsed results
        """
        result = {
            'headers': {},
            'score': 0,
            'grade': 'F',
            'api_analysis': True
        }
        
        # Extract grade using regex
        grade_match = re.search(r'Grade:\s*([A-F][+-]?)', html, re.IGNORECASE)
        if grade_match:
            result['grade'] = grade_match.group(1)
        
        # Extract score using regex
        score_match = re.search(r'Score:\s*(\d+)', html, re.IGNORECASE)
        if score_match:
            result['score'] = int(score_match.group(1))
        
        return result
    
    async def _run_nikto(self, target: str) -> Optional[Dict]:
        """
        Run nikto for additional security analysis
        
        Args:
            target: Target URL
            
        Returns:
            Nikto analysis results
        """
        try:
            cmd = [
                'nikto', '-h', target,
                '-timeout', str(self.config.get('headers.timeout', 10)),
                '-Format', 'json',
                '-nointeractive',
                '-maxtime', '60'  # Limit nikto scan time
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=120  # 2 minute timeout for nikto
            )
            
            if process.returncode == 0:
                return self._parse_nikto_output(stdout.decode())
            else:
                # Try to parse partial output
                return self._parse_nikto_output(stdout.decode() + stderr.decode())
        
        except asyncio.TimeoutError:
            logger.warning("Nikto scan timed out")
        except FileNotFoundError:
            logger.debug("Nikto not found")
        except Exception as e:
            logger.debug(f"Nikto scan failed: {str(e)}")
        
        return None
    
    def _parse_nikto_output(self, output: str) -> Dict:
        """
        Parse nikto output
        
        Args:
            output: Nikto output text
            
        Returns:
            Parsed nikto results
        """
        result = {
            'findings': [],
            'total_items': 0,
            'tool': 'nikto'
        }
        
        try:
            # Try to parse as JSON first
            data = json.loads(output)
            
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    finding = {
                        'id': vuln.get('id', ''),
                        'message': vuln.get('msg', ''),
                        'uri': vuln.get('uri', ''),
                        'method': vuln.get('method', ''),
                        'severity': self._map_nikto_severity(vuln.get('id', ''))
                    }
                    result['findings'].append(finding)
                
                result['total_items'] = len(result['findings'])
        
        except json.JSONDecodeError:
            # Parse text output
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                
                # Look for vulnerability lines (usually start with + )
                if line.startswith('+ ') and any(keyword in line.lower() for keyword in 
                    ['server:', 'header', 'version', 'cookie', 'ssl', 'tls']):
                    
                    finding = {
                        'message': line[2:],  # Remove '+ ' prefix
                        'severity': 'info',
                        'source': 'nikto_text'
                    }
                    result['findings'].append(finding)
            
            result['total_items'] = len(result['findings'])
        
        return result
    
    def _map_nikto_severity(self, nikto_id: str) -> str:
        """
        Map nikto finding ID to severity level
        
        Args:
            nikto_id: Nikto finding ID
            
        Returns:
            Severity level
        """
        # High severity findings
        if any(id_part in nikto_id for id_part in ['000001', '000002', '000003']):
            return 'high'
        
        # Medium severity findings  
        elif any(id_part in nikto_id for id_part in ['000020', '000025', '000030']):
            return 'medium'
        
        # Default to low
        return 'low'
    
    def _analyze_collected_headers(self, headers: Dict[str, str]) -> Dict:
        """
        Analyze collected headers for security issues
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            Analysis results with issues, score, and grade
        """
        issues = []
        score = 0
        max_score = 100
        
        # Check for missing security headers
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                if header_info['required']:
                    severity = header_info['severity']
                    issue = {
                        'type': 'missing_header',
                        'header': header_name,
                        'name': header_info['name'],
                        'description': f"Missing {header_info['name']}: {header_info['description']}",
                        'severity': severity,
                        'owasp_category': self.owasp_category,
                        'recommendation': f"Add {header_name} header to improve security"
                    }
                    issues.append(issue)
                    
                    # Deduct points based on severity
                    if severity == 'high':
                        score -= 25
                    elif severity == 'medium':
                        score -= 15
                    else:
                        score -= 5
            else:
                # Header is present, validate its value
                header_value = headers[header_name]
                validation_result = self._validate_header_value(header_name, header_value)
                
                if validation_result['issues']:
                    issues.extend(validation_result['issues'])
                    score -= validation_result['score_penalty']
                else:
                    # Award points for good headers
                    if header_info['severity'] == 'high':
                        score += 25
                    elif header_info['severity'] == 'medium':
                        score += 15
                    else:
                        score += 5
        
        # Check for dangerous headers that reveal information
        for header_name, header_info in self.dangerous_headers.items():
            if header_name in headers:
                issue = {
                    'type': 'information_disclosure',
                    'header': header_name,
                    'name': header_info['name'],
                    'description': f"{header_info['name']}: {header_info['description']}",
                    'value': headers[header_name],
                    'severity': header_info['severity'],
                    'owasp_category': self.owasp_category,
                    'recommendation': f"Remove or obfuscate {header_name} header"
                }
                issues.append(issue)
                
                # Small penalty for information disclosure
                score -= 2
        
        # Ensure score is within bounds
        final_score = max(0, min(100, score + 50))  # Base score of 50
        
        # Calculate grade
        grade = self._calculate_grade(final_score)
        
        return {
            'issues': issues,
            'score': final_score,
            'grade': grade
        }
    
    def _validate_header_value(self, header_name: str, header_value: str) -> Dict:
        """
        Validate security header values
        
        Args:
            header_name: Header name
            header_value: Header value
            
        Returns:
            Validation results
        """
        issues = []
        score_penalty = 0
        
        if header_name == 'strict-transport-security':
            # HSTS validation
            if 'max-age=' not in header_value:
                issues.append({
                    'type': 'invalid_header_value',
                    'header': header_name,
                    'description': 'HSTS header missing max-age directive',
                    'severity': 'medium',
                    'recommendation': 'Add max-age directive to HSTS header'
                })
                score_penalty = 10
            else:
                # Extract max-age value
                import re
                max_age_match = re.search(r'max-age=(\d+)', header_value)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        issues.append({
                            'type': 'weak_header_value',
                            'header': header_name,
                            'description': f'HSTS max-age is too short ({max_age} seconds)',
                            'severity': 'low',
                            'recommendation': 'Set HSTS max-age to at least 31536000 seconds (1 year)'
                        })
                        score_penalty = 5
        
        elif header_name == 'content-security-policy':
            # CSP validation
            if 'unsafe-inline' in header_value or 'unsafe-eval' in header_value:
                issues.append({
                    'type': 'weak_header_value',
                    'header': header_name,
                    'description': 'CSP contains unsafe directives',
                    'severity': 'medium',
                    'recommendation': 'Remove unsafe-inline and unsafe-eval from CSP'
                })
                score_penalty = 15
        
        elif header_name == 'x-frame-options':
            # X-Frame-Options validation
            valid_values = ['DENY', 'SAMEORIGIN']
            if header_value.upper() not in valid_values and not header_value.upper().startswith('ALLOW-FROM'):
                issues.append({
                    'type': 'invalid_header_value',
                    'header': header_name,
                    'description': f'Invalid X-Frame-Options value: {header_value}',
                    'severity': 'low',
                    'recommendation': 'Use DENY or SAMEORIGIN for X-Frame-Options'
                })
                score_penalty = 5
        
        return {
            'issues': issues,
            'score_penalty': score_penalty
        }
    
    def _calculate_grade(self, score: int) -> str:
        """
        Calculate letter grade based on score
        
        Args:
            score: Numeric score (0-100)
            
        Returns:
            Letter grade (A+ to F)
        """
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()