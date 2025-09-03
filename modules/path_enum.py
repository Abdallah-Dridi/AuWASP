#!/usr/bin/env python3
"""
Path Enumeration Module
Orchestrates ffuf and gobuster for sensitive path discovery, with a custom
fallback mechanism. It analyzes results to provide risk context.
"""

import asyncio
import json
import logging
import random
import subprocess
import tempfile
import datetime
import sys
import httpx
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin
from .utils import ConfigManager # Import the real ConfigManager

# Setup basic logging
logger = logging.getLogger(__name__)


class PathEnumerator:
    """
    Path enumeration using ffuf and gobuster, with analysis.
    """

    def __init__(self, config: ConfigManager):
        """
        Initialize path enumerator

        Args:
            config: Configuration manager instance
        """
        self.config = config
        self.owasp_categories = {
            'admin': "A01:2021 – Broken Access Control",
            'backup': "A05:2021 – Security Misconfiguration",
            'config': "A05:2021 – Security Misconfiguration",
            'debug': "A04:2021 - Insecure Design",
            'api': "A01:2021 – Broken Access Control",
            'upload': "A08:2021 – Software and Data Integrity Failures"
        }
        self.builtin_wordlist = [
            'admin', 'administrator', 'admin.php', 'admin.html',
            'login', 'login.php', 'login.html', 'signin',
            'api', 'v1', 'v2', 'rest', 'graphql',
            'config', 'configuration', 'settings', 'setup',
            'backup', 'backups', 'bak', 'old', 'tmp',
            'upload', 'uploads', 'files', 'download',
            'test', 'testing', 'dev', 'development',
            'debug', 'logs', 'log', 'error',
            'db', 'database', 'sql', 'mysql',
            'phpmyadmin', 'pma', 'adminer',
            'wp-admin', 'wp-content', 'wp-includes',
            'assets', 'static', 'js', 'css', 'img',
            'robots.txt', 'sitemap.xml', '.htaccess', '.env',
            'readme', 'readme.txt', 'changelog',
            'docs', 'documentation', 'help',
            'contact', 'about', 'profile', 'account'
        ]
        self.sensitive_patterns = {
            'high_risk': [
                'admin', 'administrator', 'manage', 'control', 'config',
                'backup', 'db', 'database', 'sql', '.env', '.git', 'secret'
            ],
            'medium_risk': [
                'login', 'signin', 'auth', 'user', 'api', 'upload',
                'test', 'dev', 'debug', 'log', 'pma', 'phpmyadmin'
            ],
            'low_risk': [
                'doc', 'help', 'info', 'readme', 'changelog'
            ]
        }

    async def enumerate_paths(self, target: str, progress=None, task_id=None) -> List[Dict]:
        """
        Enumerate paths using available tools, orchestrating the process.

        Args:
            target: Target URL
            progress: Optional progress tracker
            task_id: Optional task ID for progress updates

        Returns:
            A list of dictionaries, each representing a discovered and analyzed path.
        """
        results = []
        logger.info(f"Starting path enumeration on {target}")

        try:
            # Try ffuf first
            if progress and task_id:
                progress.update(task_id, description="Running ffuf...")
            try:
                ffuf_results = await self._run_ffuf(target)
                results.extend(ffuf_results)
                logger.info(f"ffuf found {len(ffuf_results)} potential paths.")
            except Exception as e:
                logger.warning(f"ffuf failed or was not found. Error: {e}")

            # Fall back to gobuster
            if not results:
                if progress and task_id:
                    progress.update(task_id, description="ffuf failed, trying gobuster...")
                logger.info("ffuf found nothing or failed, trying gobuster...")
                try:
                    gobuster_results = await self._run_gobuster(target)
                    results.extend(gobuster_results)
                    logger.info(f"gobuster found {len(gobuster_results)} potential paths.")
                except Exception as e:
                    logger.warning(f"gobuster failed or was not found. Error: {e}")

            # Fallback to custom enumeration
            if not results:
                if progress and task_id:
                    progress.update(task_id, description="Primary tools failed, running custom scan...")
                logger.warning("Primary tools failed or found nothing, running basic custom enumeration.")
                custom_results = await self._custom_enumeration(target)
                results.extend(custom_results)
                logger.info(f"Custom enumeration found {len(custom_results)} paths.")

            # Analyze and return results
            analyzed_results = self._analyze_discovered_paths(results)
            logger.info(f"Path enumeration completed. Found {len(analyzed_results)} interesting paths after analysis.")
            if progress and task_id:
                progress.update(task_id, description=f"Path enumeration complete, {len(analyzed_results)} paths found.")
            return analyzed_results

        except Exception as e:
            logger.error(f"A critical error occurred during path enumeration: {e}")
            return []
    
    async def _run_ffuf(self, target: str) -> List[Dict]:
        """Runs ffuf and parses its JSON output."""
        wordlist_path = self._get_wordlist()
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as output_file:
            output_filepath = Path(output_file.name)

        cmd = [
            'ffuf',
            '-u', f'{target}/FUZZ',
            '-w', str(wordlist_path),
            '-o', str(output_filepath),
            '-of', 'json',
            '-t', str(self.config.get('path_enum.threads', 50)),
            '-timeout', str(self.config.get('path_enum.timeout', 10)),
            '-mc', self.config.get('path_enum.status_codes', '200,204,301,302,307,401,403,405'),
            '-H', f'User-Agent: {random.choice(self.config.get("general.user_agents", ["ffuf-scanner"]))}',
            '-s' # Silent mode, suppress banner
        ]
        logger.debug(f"Running ffuf: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.config.get('path_enum.max_time', 300)
            )
            if process.returncode != 0:
                logger.debug(f"ffuf exited with code {process.returncode}: {stderr.decode()}")

            return self._parse_ffuf_output(output_filepath)
        except FileNotFoundError:
            raise Exception("ffuf command not found. Please ensure it's installed and in your PATH.")
        except asyncio.TimeoutError:
            logger.warning("ffuf process timed out.")
            return []
        finally:
            if output_filepath.exists():
                output_filepath.unlink()
            if "temp_wordlist" in str(wordlist_path):
                wordlist_path.unlink()

    def _parse_ffuf_output(self, output_file: Path) -> List[Dict]:
        """Parses the JSON output file from ffuf."""
        if not output_file.exists() or output_file.stat().st_size == 0:
            return []
        with open(output_file, 'r') as f:
            data = json.load(f)
        return [
            {
                'url': result.get('url', ''),
                'path': result.get('input', {}).get('FUZZ', ''),
                'status_code': result.get('status', 0),
                'length': result.get('length', 0),
                'redirect': result.get('redirectlocation'),
                'tool': 'ffuf',
            } for result in data.get('results', [])
        ]

    async def _run_gobuster(self, target: str) -> List[Dict]:
        """Runs gobuster and parses its text output."""
        wordlist_path = self._get_wordlist()
        cmd = [
            'gobuster', 'dir',
            '-u', target,
            '-w', str(wordlist_path),
            '-t', str(self.config.get('path_enum.threads', 50)),
            '--timeout', f"{self.config.get('path_enum.timeout', 10)}s",
            '-s', self.config.get('path_enum.status_codes', '200,204,301,302,307,401,403,405'),
            '-a', random.choice(self.config.get('general.user_agents', ['gobuster-scanner'])),
            '--no-error',
            '-q'
        ]
        logger.debug(f"Running gobuster: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.config.get('path_enum.max_time', 300)
            )
            if process.returncode != 0:
                logger.debug(f"gobuster exited with code {process.returncode}: {stderr.decode()}")

            return self._parse_gobuster_output(stdout.decode(), target)
        except FileNotFoundError:
            raise Exception("gobuster command not found. Please ensure it's installed and in your PATH.")
        except asyncio.TimeoutError:
            logger.warning("gobuster process timed out.")
            return []
        finally:
            if "temp_wordlist" in str(wordlist_path):
                wordlist_path.unlink()

    def _parse_gobuster_output(self, output: str, target: str) -> List[Dict]:
        """Parses the text output from gobuster."""
        results = []
        for line in output.strip().split('\n'):
            if not line or '(Status: ' not in line:
                continue
            parts = line.split()
            path = parts[0]
            status = int(parts[2].strip(')'))
            length = int(parts[4].strip(']')) if len(parts) > 4 else 0
            results.append({
                'url': urljoin(target, path),
                'path': path,
                'status_code': status,
                'length': length,
                'redirect': None,
                'tool': 'gobuster',
            })
        return results

    async def _custom_enumeration(self, target: str) -> List[Dict]:
        """A simple fallback enumerator using httpx."""
        results = []
        async with httpx.AsyncClient(verify=False) as client:
            tasks = [self._test_path_exists(client, target, path) for path in self.builtin_wordlist]
            path_results = await asyncio.gather(*tasks)
            results = [res for res in path_results if res is not None]
        return results

    async def _test_path_exists(self, client: httpx.AsyncClient, base_url: str, path: str) -> Optional[Dict]:
        """Uses httpx to test if a single path exists."""
        test_url = urljoin(base_url, path)
        try:
            user_agent = random.choice(self.config.get('general.user_agents', ['Custom-Scanner']))
            resp = await client.head(test_url, headers={'User-Agent': user_agent}, timeout=5, follow_redirects=False)

            if resp.status_code != 404:
                return {
                    'url': str(resp.url),
                    'path': path,
                    'status_code': resp.status_code,
                    'length': int(resp.headers.get('content-length', 0)),
                    'redirect': resp.headers.get('location'),
                    'tool': 'custom_fallback',
                }
        except httpx.RequestError as e:
            logger.debug(f"Custom scan error for {test_url}: {e}")
        return None

    def _analyze_discovered_paths(self, results: List[Dict]) -> List[Dict]:
        """
        Analyzes raw results to add risk level and OWASP category.
        """
        analyzed = []
        for res in results:
            path = res['path'].lower()
            res['risk'] = 'informational'
            res['owasp_category'] = 'N/A'
            res['timestamp'] = self._get_timestamp()

            for risk_level, patterns in self.sensitive_patterns.items():
                for pattern in patterns:
                    if pattern in path:
                        res['risk'] = risk_level
                        if pattern in self.owasp_categories:
                            res['owasp_category'] = self.owasp_categories[pattern]
                        analyzed.append(res)
                        goto_next_result = True
                        break
                else:
                    continue
                break
        return analyzed

    def _get_wordlist(self) -> Path:
        """
        Provides a path to a wordlist.
        """
        configured_path = self.config.get('path_enum.wordlist')
        if configured_path and Path(configured_path).is_file():
            logger.info(f"Using configured wordlist: {configured_path}")
            return Path(configured_path)

        logger.info("Using built-in wordlist as a fallback.")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', prefix='temp_wordlist_') as f:
            f.write('\n'.join(self.builtin_wordlist))
            return Path(f.name)

    def _get_timestamp(self) -> str:
        """Returns the current timestamp in ISO 8601 format."""
        return datetime.datetime.now(datetime.timezone.utc).isoformat()