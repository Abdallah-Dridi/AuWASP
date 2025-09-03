#!/usr/bin/env python3
"""
Web Crawler Module
Orchestrates gospider and hakrawler for comprehensive URL discovery
"""

import asyncio
import json
import logging
import random
import subprocess
import tempfile
from pathlib import Path
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class WebCrawler:
    """
    Web crawler that uses gospider and hakrawler for URL discovery
    """
    
    def __init__(self, config):
        """
        Initialize the web crawler
        
        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
    
    async def crawl(self, target: str) -> Dict[str, str]:
        """
        Crawl target using available tools and merge results, fetching page content.

        Args:
            target: Target URL to crawl

        Returns:
            Dictionary mapping discovered URLs to their HTML content
        """
        logger.info(f"Starting crawl of {target}")

        crawled_urls = set()
        url_to_content = {}

        # Try gospider first
        try:
            gospider_urls = await self._run_gospider(target)
            crawled_urls.update(gospider_urls)
            logger.info(f"Gospider found {len(gospider_urls)} URLs")
        except Exception as e:
            logger.warning(f"Gospider failed: {str(e)}")

        # Try hakrawler as backup/supplement
        try:
            hakrawler_urls = await self._run_hakrawler(target)
            crawled_urls.update(hakrawler_urls)
            logger.info(f"Hakrawler found {len(hakrawler_urls)} URLs")
        except Exception as e:
            logger.warning(f"Hakrawler failed: {str(e)}")

        # If both tools failed, try basic curl/wget crawling
        if not crawled_urls:
            logger.warning("Primary crawlers failed, attempting basic discovery")
            basic_urls = await self._basic_crawl(target)
            crawled_urls.update(basic_urls)

        # Now, fetch content for all unique URLs found
        logger.info(f"Fetching content for {len(crawled_urls)} unique URLs...")
        for url in crawled_urls:
            content = await self._fetch_page_content(url)
            if content:
                url_to_content[url] = content

        logger.info(f"Successfully fetched content for {len(url_to_content)} URLs")
        return url_to_content
    async def _fetch_page_content(self, url: str) -> Optional[str]:
        """Fetches the HTML content of a given URL."""
        try:
            cmd = ['curl', '-s', '-L', '--user-agent', random.choice(self.user_agents), '--max-time', '10', url]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                return stdout.decode(errors='ignore')
        except Exception as e:
            logger.debug(f"Failed to fetch content for {url}: {str(e)}")
        return None
    
    async def _run_gospider(self, target: str) -> Set[str]:
        """
        Run gospider for URL discovery
        
        Args:
            target: Target URL
            
        Returns:
            Set of discovered URLs
        """
        urls = set()
        
        # Gospider command configuration
        # In the _run_gospider method...
        cmd = [
            'gospider',
            '-s', target,
            '-c', str(self.config.get('crawler.concurrency', 10)),
            '-d', str(self.config.get('crawler.depth', 3)),
            '--user-agent', random.choice(self.user_agents),
            '--timeout', str(self.config.get('crawler.timeout', 10)),
            # FIX: Pass the delay as a string representation of an integer, without the "s".
            '--delay', str(self.config.get('crawler.delay', 1)),
            '--robots',
            '--sitemap',
            '--json',
            '--include-subs' if self.config.get('crawler.include_subdomains', False) else '--no-redirect'
        ]
        
        # Add custom headers if configured
        headers = self.config.get('crawler.headers', {})
        for key, value in headers.items():
            cmd.extend(['-H', f"{key}: {value}"])
        
        logger.debug(f"Running gospider: {' '.join(cmd)}")
        
        try:
            # Run gospider
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Gospider failed with return code {process.returncode}")
                logger.error(f"Stderr: {stderr.decode()}")
                return urls
            
            # Parse JSON output
            for line in stdout.decode().strip().split('\n'):
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    if 'output' in data:
                        url = data['output']
                        if self._is_valid_url(url):
                            urls.add(url)
                except json.JSONDecodeError:
                    # Sometimes gospider outputs non-JSON lines
                    continue
        
        except FileNotFoundError:
            raise Exception("Gospider not found. Please install gospider.")
        except Exception as e:
            logger.error(f"Error running gospider: {str(e)}")
            raise
        
        return urls
    
    async def _run_hakrawler(self, target: str) -> Set[str]:
        """
        Run hakrawler for URL discovery
        
        Args:
            target: Target URL
            
        Returns:
            Set of discovered URLs
        """
        urls = set()
        
        # Hakrawler command configuration
        cmd = [
            'hakrawler',
            '-url', target,
            '-depth', str(self.config.get('crawler.depth', 3)),
            '-user-agent', random.choice(self.user_agents),
            '-timeout', str(self.config.get('crawler.timeout', 10)),
            '-delay', str(self.config.get('crawler.delay', 1)),
            '-json'
        ]
        
        # Add scope options
        if self.config.get('crawler.include_subdomains', False):
            cmd.append('-subs')
        
        if not self.config.get('crawler.follow_external', False):
            cmd.append('-insecure')  # This actually keeps it to same domain in hakrawler
        
        logger.debug(f"Running hakrawler: {' '.join(cmd)}")
        
        try:
            # Run hakrawler
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"Hakrawler completed with return code {process.returncode}")
                # Hakrawler sometimes returns non-zero even on success
            
            # Parse output (hakrawler outputs one URL per line when using -json)
            for line in stdout.decode().strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Try to parse as JSON first
                    data = json.loads(line)
                    if isinstance(data, dict) and 'url' in data:
                        url = data['url']
                    elif isinstance(data, str):
                        url = data
                    else:
                        continue
                except json.JSONDecodeError:
                    # If not JSON, treat as plain URL
                    url = line
                
                if self._is_valid_url(url):
                    urls.add(url)
        
        except FileNotFoundError:
            raise Exception("Hakrawler not found. Please install hakrawler.")
        except Exception as e:
            logger.error(f"Error running hakrawler: {str(e)}")
            raise
        
        return urls
    
    async def _basic_crawl(self, target: str) -> Set[str]:
        """
        Basic crawling using curl/wget as fallback
        
        Args:
            target: Target URL
            
        Returns:
            Set of discovered URLs
        """
        urls = set()
        
        try:
            # Try to get robots.txt
            robots_url = urljoin(target, '/robots.txt')
            robots_urls = await self._crawl_robots(robots_url)
            urls.update(robots_urls)
            
            # Try to get sitemap.xml
            sitemap_url = urljoin(target, '/sitemap.xml')
            sitemap_urls = await self._crawl_sitemap(sitemap_url)
            urls.update(sitemap_urls)
            
            # Try common paths
            common_paths = [
                '/', '/index.html', '/index.php', '/home', '/login', '/admin',
                '/api', '/docs', '/documentation', '/help', '/about', '/contact'
            ]
            
            for path in common_paths:
                url = urljoin(target, path)
                if await self._check_url_exists(url):
                    urls.add(url)
        
        except Exception as e:
            logger.error(f"Basic crawl failed: {str(e)}")
        
        return urls
    
    async def _crawl_robots(self, robots_url: str) -> Set[str]:
        """
        Extract URLs from robots.txt
        
        Args:
            robots_url: URL to robots.txt
            
        Returns:
            Set of URLs found in robots.txt
        """
        urls = set()
        
        try:
            cmd = ['curl', '-s', '-L', '--user-agent', random.choice(self.user_agents), robots_url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                content = stdout.decode()
                parsed_url = urlparse(robots_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith(('Disallow:', 'Allow:', 'Sitemap:')):
                        path = line.split(':', 1)[1].strip()
                        if path.startswith('/'):
                            urls.add(urljoin(base_url, path))
                        elif path.startswith('http'):
                            urls.add(path)
        
        except Exception as e:
            logger.debug(f"Failed to crawl robots.txt: {str(e)}")
        
        return urls
    
    async def _crawl_sitemap(self, sitemap_url: str) -> Set[str]:
        """
        Extract URLs from sitemap.xml
        
        Args:
            sitemap_url: URL to sitemap.xml
            
        Returns:
            Set of URLs found in sitemap.xml
        """
        urls = set()
        
        try:
            cmd = ['curl', '-s', '-L', '--user-agent', random.choice(self.user_agents), sitemap_url]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                content = stdout.decode()
                
                # Simple regex-like extraction for <loc> tags
                import re
                loc_pattern = r'<loc>(.*?)</loc>'
                matches = re.findall(loc_pattern, content, re.IGNORECASE)
                
                for match in matches:
                    url = match.strip()
                    if self._is_valid_url(url):
                        urls.add(url)
        
        except Exception as e:
            logger.debug(f"Failed to crawl sitemap.xml: {str(e)}")
        
        return urls
    
    async def _check_url_exists(self, url: str) -> bool:
        """
        Check if a URL exists (returns 200 status)
        
        Args:
            url: URL to check
            
        Returns:
            True if URL exists and returns 200
        """
        try:
            cmd = [
                'curl', '-s', '-I', '--user-agent', random.choice(self.user_agents),
                '--max-time', '5', url
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                response = stdout.decode()
                return 'HTTP/' in response and ('200 OK' in response or '301 ' in response or '302 ' in response)
            
        except Exception as e:
            logger.debug(f"Failed to check URL {url}: {str(e)}")
        
        return False
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate if URL is properly formatted and should be included
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid
        """
        if not url or not isinstance(url, str):
            return False
        
        try:
            parsed = urlparse(url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Only http/https
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Basic URL format validation
            if len(url) > 2048:  # URLs too long are suspicious
                return False
            
            return True
            
        except Exception:
            return False