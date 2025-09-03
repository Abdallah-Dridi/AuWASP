#!/usr/bin/env python3
"""
Utilities Module
Common utilities for tool checking, configuration management, and helpers
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class ToolChecker:
    """
    Utility to check if required external tools are installed
    """
    
    def __init__(self):
        """Initialize tool checker"""
        self.required_tools = {
            'primary': {
                'gospider': 'Web crawler for URL discovery',
                'sqlmap': 'SQL injection testing tool',
                'curl': 'HTTP client for basic requests'
            },
            'alternative': {
                'hakrawler': 'Alternative web crawler',
                'ffuf': 'Fast web fuzzer for path enumeration',
                'gobuster': 'Alternative path enumeration tool',
                'nikto': 'Web vulnerability scanner'
            }
        }
    
    def check_required_tools(self) -> List[str]:
        """
        Check if required tools are installed
        
        Returns:
            List of missing tools
        """
        missing_tools = []
        
        # Check primary tools (essential)
        for tool, description in self.required_tools['primary'].items():
            if not self._is_tool_installed(tool):
                missing_tools.append(f"{tool} - {description}")
        
        # Check alternative tools (warn if missing)
        missing_alternatives = []
        for tool, description in self.required_tools['alternative'].items():
            if not self._is_tool_installed(tool):
                missing_alternatives.append(f"{tool} - {description}")
        
        if missing_alternatives:
            logger.warning("Optional tools not found (functionality may be limited):")
            for tool in missing_alternatives:
                logger.warning(f"  - {tool}")
        
        return missing_tools
    
    def _is_tool_installed(self, tool_name: str) -> bool:
        """
        Check if a tool is installed and accessible
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is installed
        """
        try:
            # Use shutil.which to check if tool is in PATH
            tool_path = shutil.which(tool_name)
            if tool_path:
                logger.debug(f"Found {tool_name} at {tool_path}")
                return True
            
            # For some tools, try alternative checks
            if tool_name == 'sqlmap':
                # Check if sqlmap.py is available
                sqlmap_py = shutil.which('sqlmap.py')
                if sqlmap_py:
                    logger.debug(f"Found sqlmap.py at {sqlmap_py}")
                    return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Error checking for {tool_name}: {str(e)}")
            return False
    
    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """
        Get version information for a tool
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Version string or None if not available
        """
        version_commands = {
            'gospider': ['gospider', '--version'],
            'hakrawler': ['hakrawler', '-version'],
            'sqlmap': ['sqlmap', '--version'],
            'ffuf': ['ffuf', '-V'],
            'gobuster': ['gobuster', 'version'],
            'nikto': ['nikto', '-Version'],
            'curl': ['curl', '--version']
        }
        
        if tool_name not in version_commands:
            return None
        
        try:
            result = subprocess.run(
                version_commands[tool_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                # Extract version from output (first line usually contains version)
                first_line = output.split('\n')[0]
                return first_line
            
        except Exception as e:
            logger.debug(f"Error getting version for {tool_name}: {str(e)}")
        
        return None


class ConfigManager:
    """
    Configuration manager for handling scanner settings
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self.config = self._load_default_config()
        
        if config_file:
            self._load_config_file(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """
        Load default configuration
        
        Returns:
            Default configuration dictionary
        """
        return {
            # Crawler settings
            'crawler': {
                'concurrency': 10,
                'depth': 3,
                'timeout': 15,
                'delay': 1,
                'include_subdomains': True,
                'follow_external': False,
                'headers': {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive'
                }
            },
            
            # Filter settings
            'filter': {
                'include_subdomains': True,
                'max_parameters': 10,
                'exclude_extensions': ['.jpg', '.png', '.css', '.js', '.pdf', '.zip'],
                'sensitive_keywords': ['admin', 'login', 'api', 'upload', 'config']
            },
            
            # SQL injection settings
            'sqlmap': {
                'timeout': 30,
                'threads': 5,
                'level': 1,
                'risk': 1,
                'technique': 'BEUSTQ',  # All techniques
                'delay': 0,
                'retries': 3,
                'batch': True,
                'random_agent': True
            },
            
            # XSS settings
            'xss': {
                'timeout': 20,
                'threads': 10,
                'crawl_depth': 2,
                'payload_level': 6,
                'skip_dom': False,
                'blind': False
            },
            
            # Path enumeration settings
            'path_enum': {
                'wordlist': '/usr/share/wordlists/dirb/common.txt',
                'extensions': ['php', 'html', 'js', 'txt', 'xml', 'json'],
                'threads': 50,
                'timeout': 10,
                'delay': 0,
                'status_codes': '200,204,301,302,307,401,403,405,500'
            },
            
            # Header analysis settings
            'headers': {
                'timeout': 10,
                'check_redirects': True,
                'use_api': True,  # Use securityheaders.com API
                'api_timeout': 15
            },
            
            # Reporting settings
            'reporting': {
                'format': 'html',
                'include_screenshots': False,
                'severity_threshold': 'low',
                'group_by_type': True
            },
            
            # General settings
            'general': {
                'max_scan_time': 3600,  # 1 hour max
                'output_format': 'json',
                'verbose': False,
                'user_agents': [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                ]
            }
        }
    
    def _load_config_file(self, config_file: str):
        """
        Load configuration from file
        
        Args:
            config_file: Path to configuration file
        """
        try:
            config_path = Path(config_file)
            if not config_path.exists():
                logger.warning(f"Configuration file not found: {config_file}")
                return
            
            with open(config_path, 'r') as f:
                if config_file.endswith('.json'):
                    user_config = json.load(f)
                else:
                    # Assume YAML if not JSON
                    try:
                        import yaml
                        user_config = yaml.safe_load(f)
                    except ImportError:
                        logger.error("PyYAML not installed. Cannot load YAML config file.")
                        return
            
            # Merge user config with defaults
            self._merge_config(self.config, user_config)
            logger.info(f"Configuration loaded from {config_file}")
            
        except Exception as e:
            logger.error(f"Error loading configuration file: {str(e)}")
    
    def _merge_config(self, default: Dict, user: Dict):
        """
        Recursively merge user configuration with defaults
        
        Args:
            default: Default configuration dictionary
            user: User configuration dictionary
        """
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'crawler.timeout')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                value = value[k]
            
            return value
            
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'crawler.timeout')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to parent dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the final value
        config[keys[-1]] = value
    
    def save(self, output_file: str):
        """
        Save current configuration to file
        
        Args:
            output_file: Path to output file
        """
        try:
            output_path = Path(output_file)
            
            with open(output_path, 'w') as f:
                if output_file.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                else:
                    # Assume YAML
                    try:
                        import yaml
                        yaml.safe_dump(self.config, f, default_flow_style=False, indent=2)
                    except ImportError:
                        logger.error("PyYAML not installed. Saving as JSON.")
                        json.dump(self.config, f, indent=2)
            
            logger.info(f"Configuration saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")


class RateLimiter:
    """
    Simple rate limiter for controlling request frequency
    """
    
    def __init__(self, requests_per_second: float = 1.0):
        """
        Initialize rate limiter
        
        Args:
            requests_per_second: Maximum requests per second
        """
        self.requests_per_second = requests_per_second
        if requests_per_second == float('inf') or requests_per_second <= 0:
            self.min_interval = 0  # No delay for infinite or invalid rates
        else:
            self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
    
    async def wait_if_needed(self):
        """
        Wait if necessary to respect rate limit
        """
        import asyncio
        import time
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_interval:
            wait_time = self.min_interval - time_since_last
            await asyncio.sleep(wait_time)
        
        self.last_request_time = time.time()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem usage
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    
    # Remove or replace unsafe characters
    unsafe_chars = r'[<>:"/\\|?*\x00-\x1f]'
    sanitized = re.sub(unsafe_chars, '_', filename)
    
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    
    # Ensure it's not empty
    if not sanitized:
        sanitized = 'unnamed_file'
    
    return sanitized


def format_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: Full URL
        
    Returns:
        Domain name
    """
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain.lower()
    
    except Exception:
        return ''


def is_valid_target(target: str) -> bool:
    """
    Validate if target is a proper URL or domain
    
    Args:
        target: Target URL or domain
        
    Returns:
        True if target is valid
    """
    from urllib.parse import urlparse
    import re
    
    try:
        # If it looks like a URL, parse it
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return bool(parsed.netloc)
        
        # Otherwise, treat as domain and validate
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, target))
    
    except Exception:
        return False