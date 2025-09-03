#!/usr/bin/env python3
"""
URL Filter Module
Filters and categorizes discovered URLs for targeted testing
"""

import logging
import re
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class URLFilter:
    """
    URL filter that categorizes URLs for different types of security testing
    """

    def __init__(self, config):
        """
        Initialize the URL filter
        """
        self.config = config
        self.excluded_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.mp3', '.mp4', '.avi', '.mov', '.wav',
            '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot'
        }
        self.sensitive_patterns = [
            r'/admin', r'/administrator', r'/manage',
            r'/api', r'/v1/', r'/v2/', r'/rest/',
            r'/login', r'/signin', r'/auth',
            r'/upload', r'/file', r'/download',
            r'/config', r'/settings', r'/setup',
            r'/debug', r'/test', r'/dev'
        ]
        self.interesting_params = {
            'sql': ['id', 'uid', 'user', 'query', 'q', 'search', 'filter', 'sort', 'order'],
            'xss': ['name', 'title', 'msg', 'comment', 'text', 'content', 'q', 'search'],
            'lfi': ['file', 'filename', 'path', 'dir', 'include', 'page', 'template'],
            'cmd': ['cmd', 'exec', 'system', 'shell', 'run', 'ping', 'host']
        }

    def filter_urls(self, url_to_content: Dict[str, str], target_domain: str) -> Dict[str, List]:
        """
        Filter and categorize URLs based on their content for security testing.

        Args:
            url_to_content: A dictionary mapping discovered URLs to their HTML content.
            target_domain: The original target domain for scope validation.

        Returns:
            A dictionary containing categorized URLs.
        """
        urls = list(url_to_content.keys())
        logger.info(f"Filtering {len(urls)} discovered URLs")

        target_parsed = urlparse(target_domain)
        target_host = target_parsed.netloc.lower().split(':')[0]

        filtered_results = {
            'static': [], 'dynamic': [], 'forms': [], 'sensitive': [],
            'api_endpoints': [], 'excluded': [], 'all_in_scope': []
        }
        seen_urls = set()
        seen_form_signatures = set()

        for url, content in url_to_content.items():
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                parsed_url = urlparse(url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    continue

                url_host = parsed_url.netloc.lower().split(':')[0]
                if not self._is_in_scope(url_host, target_host):
                    filtered_results['excluded'].append({'url': url, 'reason': 'out_of_scope'})
                    continue

                filtered_results['all_in_scope'].append(url)

                if self._has_excluded_extension(parsed_url.path):
                    filtered_results['static'].append(url)
                    continue
                
                # Extract forms from content
                if content:
                    soup = BeautifulSoup(content, 'lxml')
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action', '')
                        method = form.get('method', 'get').upper()
                        inputs = []
                        for inp in form.find_all('input'):
                            if inp.get('name'):
                                inputs.append({
                                    'name': inp.get('name'),
                                    'type': inp.get('type', 'text'),
                                    'value': inp.get('value', '')
                                })
                        
                        form_info = {
                            'url': urljoin(url, action),
                            'action': urljoin(url, action),
                            'method': method,
                            'inputs': inputs,
                            'source_url': url
                        }
                        
                        signature = f"{action}|{method}|{'|'.join(sorted([inp['name'] for inp in inputs]))}"
                        
                        if signature not in seen_form_signatures:
                            # Check for interesting parameters
                            param_names = [inp['name'] for inp in inputs]
                            form_info['sql_params'] = []
                            form_info['xss_params'] = []
                            
                            for param_name in param_names:
                                for attack_type, param_list in self.interesting_params.items():
                                    if any(interesting_param in param_name for interesting_param in param_list):
                                        form_info[f'{attack_type}_params'].append(param_name)
                            
                            filtered_results['forms'].append(form_info)
                            seen_form_signatures.add(signature)

                self._categorize_url(url, parsed_url, filtered_results)

            except Exception as e:
                logger.debug(f"Error processing URL {url}: {str(e)}")
                continue

        # Custom duplicate removal
        for category, items in filtered_results.items():
            if category == 'excluded':
                continue
            
            unique_items = {}
            for item in items:
                if isinstance(item, dict):
                    if 'url' in item:
                        unique_items[item['url']] = item
                    elif 'action' in item:
                        unique_items[item['action']] = item
                else:
                    if item not in unique_items:
                        unique_items[item] = item
            
            filtered_results[category] = sorted(list(unique_items.values()), key=lambda x: x if isinstance(x, str) else x.get('url', x.get('action', '')))

        self._log_filtering_results(filtered_results)
        return filtered_results

    def get_testing_targets(self, filtered_results: Dict, test_type: str) -> List:
        """
        Get URLs suitable for specific type of testing
        
        Args:
            filtered_results: Filtered URL results
            test_type: Type of testing ('sql', 'xss', 'lfi', 'cmd')
            
        Returns:
            List of URLs suitable for the specified test type
        """
        targets = []
        seen_urls = set()

        def add_target(target):
            url = target['url'] if isinstance(target, dict) else target
            if url not in seen_urls:
                targets.append(target)
                seen_urls.add(url)

        # Add dynamic URLs with relevant parameters
        for url_info in filtered_results.get('dynamic', []):
            if isinstance(url_info, dict):
                param_key = f'{test_type}_params'
                if url_info.get(param_key):
                    add_target(url_info)
            else:
                add_target(url_info)
        
        # Add forms for XSS and SQL testing
        if test_type in ['sql', 'xss']:
            for target in filtered_results.get('forms', []):
                add_target(target)
        
        # Add sensitive paths for various tests
        if test_type in ['sql', 'xss', 'lfi']:
            for target in filtered_results.get('sensitive', []):
                add_target(target)
        
        # Add API endpoints for SQL and XSS testing
        if test_type in ['sql', 'xss']:
            for target in filtered_results.get('api_endpoints', []):
                add_target(target)
        
        return targets

    def _is_in_scope(self, url_host: str, target_host: str) -> bool:
        """
        Check if URL is within scanning scope
        
        Args:
            url_host: Host of the URL being checked
            target_host: Original target host
            
        Returns:
            True if URL is in scope
        """
        # Exact match
        if url_host == target_host:
            return True
        
        # Subdomain check if configured
        if self.config.get('filter.include_subdomains', True):
            if url_host.endswith('.' + target_host):
                return True
        
        # www variant check
        if url_host.startswith('www.') and url_host[4:] == target_host:
            return True
        if target_host.startswith('www.') and url_host == target_host[4:]:
            return True
        
        return False
    
    def _has_excluded_extension(self, path: str) -> bool:
        """
        Check if URL path has an excluded file extension
        
        Args:
            path: URL path to check
            
        Returns:
            True if path has excluded extension
        """
        if not path:
            return False
        
        # Get file extension
        path_lower = path.lower()
        for ext in self.excluded_extensions:
            if path_lower.endswith(ext):
                return True
        
        return False
    
    def _categorize_url(self, url: str, parsed_url, filtered_results: Dict):
        """
        Categorize URL into appropriate testing categories
        
        Args:
            url: Full URL
            parsed_url: Parsed URL object
            filtered_results: Dictionary to store categorized URLs
        """
        path = parsed_url.path.lower()
        query_params = parse_qs(parsed_url.query)
        
        # Check for API endpoints
        if self._is_api_endpoint(path):
            filtered_results['api_endpoints'].append(url)
        
        # Check for sensitive paths
        if self._is_sensitive_path(path):
            filtered_results['sensitive'].append(url)
        
        # Check if URL has parameters (dynamic)
        if query_params:
            filtered_results['dynamic'].append(url)
            
            # Further categorize based on parameter names
            param_names = [param.lower() for param in query_params.keys()]
            
            # Mark potentially interesting parameters for different attack types
            url_info = {
                'url': url,
                'params': param_names,
                'sql_params': [],
                'xss_params': [],
                'lfi_params': [],
                'cmd_params': []
            }
            
            for param_name in param_names:
                for attack_type, param_list in self.interesting_params.items():
                    if any(interesting_param in param_name for interesting_param in param_list):
                        url_info[f'{attack_type}_params'].append(param_name)
            
            if any(url_info[key] for key in ['sql_params', 'xss_params', 'lfi_params', 'cmd_params']):
                filtered_results['dynamic'][-1] = url_info
    
    def _is_api_endpoint(self, path: str) -> bool:
        """
        Check if path appears to be an API endpoint
        """
        api_patterns = [
            r'/api', r'/v\d+/', r'/rest', r'/graphql', r'/json',
            r'/service', r'/webservice', r'/ws/', r'/rpc'
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        return False
    
    def _is_sensitive_path(self, path: str) -> bool:
        """
        Check if path appears to be sensitive
        """
        for pattern in self.sensitive_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        return False
    
    def _log_filtering_results(self, filtered_results: Dict):
        """
        Log the results of URL filtering
        """
        logger.info("URL filtering completed:")
        logger.info(f"  - Total in scope: {len(filtered_results['all_in_scope'])}")
        logger.info(f"  - Static files: {len(filtered_results['static'])}")
        logger.info(f"  - Dynamic URLs: {len(filtered_results['dynamic'])}")
        logger.info(f"  - Form pages: {len(filtered_results['forms'])}")
        logger.info(f"  - Sensitive paths: {len(filtered_results['sensitive'])}")
        logger.info(f"  - API endpoints: {len(filtered_results['api_endpoints'])}")
        logger.info(f"  - Excluded URLs: {len(filtered_results['excluded'])}")