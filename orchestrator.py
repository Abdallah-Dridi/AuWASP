#!/usr/bin/env python3
"""
OWASP Top 10 Web Scanner Orchestrator
A comprehensive security testing tool that orchestrates multiple CLI tools
for automated web application security assessment.

Author: Security Automation Team
License: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

# Import our modules
from modules.crawler import WebCrawler
from modules.filter import URLFilter
from modules.sql_injection import SQLInjectionTester
from modules.xss import XSSTester
from modules.path_enum import PathEnumerator
from modules.header_check import HeaderAnalyzer
from modules.report import ReportGenerator
from modules.utils import ToolChecker, ConfigManager

# Setup rich console for beautiful output
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("owasp_scanner")


class OWASPScanner:
    """
    Main orchestrator class that coordinates all security testing modules
    """

    def __init__(self, target: str, output_dir: str = "results", config_file: str = None):
        """
        Initialize the OWASP scanner

        Args:
            target: Target URL or domain to scan
            output_dir: Directory to store results
            config_file: Optional configuration file path
        """
        self.target = target
        self.output_dir = Path(output_dir)
        self.config_file = config_file

        # Create output directory
        self.output_dir.mkdir(exist_ok=True, parents=True)

        # Initialize configuration
        self.config = ConfigManager(config_file)

        # Initialize modules
        self.crawler = WebCrawler(self.config)
        self.url_filter = URLFilter(self.config)
        self.sql_tester = SQLInjectionTester(self.config)
        self.xss_tester = XSSTester(self.config)
        self.path_enum = PathEnumerator(self.config)
        self.header_analyzer = HeaderAnalyzer(self.config)
        self.report_gen = ReportGenerator(self.config)

        # Results storage
        self.results = {
            'target': target,
            'crawled_urls': [],
            'filtered_urls': [],
            'sql_injection': [],
            'xss': [],
            'path_enumeration': [],
            'header_analysis': [],
            'summary': {}
        }

    async def run_scan(self, modules: List[str] = None) -> Dict:
        """
        Execute the complete scanning workflow

        Args:
            modules: List of specific modules to run (optional)

        Returns:
            Dictionary containing all scan results
        """
        console.print(Panel.fit(
            f"[bold blue]OWASP Top 10 Scanner[/bold blue]\n"
            f"Target: [yellow]{self.target}[/yellow]\n"
            f"Output: [green]{self.output_dir}[/green]",
            title="Security Scan Starting"
        ))

        try:
            # Step 1: Crawl target
            if not modules or 'crawler' in modules:
                await self._run_crawler()

            # Step 2: Filter URLs
            if not modules or 'filter' in modules:
                await self._run_filter()

            # Step 3: SQL Injection Testing
            if not modules or 'sql' in modules:
                await self._run_sql_injection()

            # Step 4: XSS Testing
            if not modules or 'xss' in modules:
                await self._run_xss_testing()

            # Step 5: Path Enumeration
            if not modules or 'paths' in modules:
                await self._run_path_enumeration()

            # Step 6: Header Analysis
            if not modules or 'headers' in modules:
                await self._run_header_analysis()

            # Step 7: Generate Report
            await self._generate_report()

            console.print("[bold green]✓ Scan completed successfully![/bold green]")
            return self.results

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise

    async def _run_crawler(self):
        """Run web crawler to discover URLs"""
        console.print("[bold cyan]Phase 1: Web Crawling[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Crawling and fetching content...", total=None)
            
            # crawl now returns a dictionary of {url: content}
            crawl_results = await self.crawler.crawl(self.target)
            self.results['crawled_urls'] = crawl_results
            
            progress.update(task, description=f"Found and fetched {len(crawl_results)} pages")
        
        # Save intermediate results
        self._save_intermediate_results('crawl_results.json', crawl_results)
        
        console.print(f"[green]✓ Crawling completed: {len(crawl_results)} URLs discovered and content fetched[/green]")

    async def _run_filter(self):
        """Filter and categorize discovered URLs"""
        console.print("[bold cyan]Phase 2: URL Filtering[/bold cyan]")

        # The crawler now returns a dict of {url: content}, which we pass directly
        url_to_content = self.results['crawled_urls']
        
        filtered_results = self.url_filter.filter_urls(
            url_to_content, 
            self.target
        )
        
        self.results['filtered_urls'] = filtered_results
        
        # Save filtered results
        self._save_intermediate_results('filtered_urls.json', filtered_results)
        
        console.print(f"[green]✓ URL filtering completed[/green]")
        console.print(f"  - Dynamic URLs: {len(filtered_results.get('dynamic', []))}")
        console.print(f"  - Static URLs: {len(filtered_results.get('static', []))}")
        console.print(f"  - Forms found: {len(filtered_results.get('forms', []))}")

    async def _run_sql_injection(self):
        """Run SQL injection testing on dynamic URLs and forms"""
        console.print("[bold cyan]Phase 3: SQL Injection Testing[/bold cyan]")

        # Get targets for SQL injection testing
        targets = []
        if 'dynamic' in self.results['filtered_urls']:
            targets.extend(self.results['filtered_urls']['dynamic'])
        if 'forms' in self.results['filtered_urls']:
            targets.extend(self.results['filtered_urls']['forms'])

        if not targets:
            console.print("[yellow]⚠ No dynamic URLs or forms found for SQL injection testing[/yellow]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Testing {len(targets)} targets...", total=len(targets))

            sql_results = await self.sql_tester.test_targets(targets, progress, task)
            self.results['sql_injection'] = sql_results

        # Save results
        self._save_intermediate_results('sql_injection_results.json', sql_results)

        vulnerabilities = len([r for r in sql_results if r.get('vulnerable', False)])
        console.print(f"[green]✓ SQL injection testing completed[/green]")
        console.print(f"  - Vulnerabilities found: {vulnerabilities}")

    async def _run_xss_testing(self):
        """Run XSS testing on dynamic URLs and forms"""
        console.print("[bold cyan]Phase 4: XSS Testing[/bold cyan]")

        # Get targets for XSS testing
        targets = []
        if 'dynamic' in self.results['filtered_urls']:
            targets.extend(self.results['filtered_urls']['dynamic'])
        if 'forms' in self.results['filtered_urls']:
            targets.extend(self.results['filtered_urls']['forms'])

        if not targets:
            console.print("[yellow]⚠ No dynamic URLs or forms found for XSS testing[/yellow]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Testing {len(targets)} targets...", total=len(targets))

            xss_results = await self.xss_tester.test_targets(targets, progress, task)
            self.results['xss'] = xss_results

        # Save results
        self._save_intermediate_results('xss_results.json', xss_results)

        vulnerabilities = len([r for r in xss_results if r.get('vulnerable', False)])
        console.print(f"[green]✓ XSS testing completed[/green]")
        console.print(f"  - Vulnerabilities found: {vulnerabilities}")

    async def _run_path_enumeration(self):
        """Run path enumeration for sensitive directories and files"""
        console.print("[bold cyan]Phase 5: Path Enumeration[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Enumerating paths...", total=None)

            path_results = await self.path_enum.enumerate_paths(self.target, progress, task)
            self.results['path_enumeration'] = path_results

        # Save results
        self._save_intermediate_results('path_enumeration_results.json', path_results)

        found_paths = len(path_results)
        console.print(f"[green]✓ Path enumeration completed[/green]")
        console.print(f"  - Paths discovered: {found_paths}")

    async def _run_header_analysis(self):
        """Analyze security headers"""
        console.print("[bold cyan]Phase 6: Header Analysis[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing headers...", total=None)

            header_results = await self.header_analyzer.analyze_headers(self.target, progress, task)
            self.results['header_analysis'] = header_results

        # Save results
        self._save_intermediate_results('header_analysis_results.json', header_results)

        issues = len(header_results.get('issues', []))
        console.print(f"[green]✓ Header analysis completed[/green]")
        console.print(f"  - Security issues found: {issues}")

    async def _generate_report(self):
        """Generate final comprehensive report"""
        console.print("[bold cyan]Phase 7: Report Generation[/bold cyan]")

        # Generate summary
        self.results['summary'] = self._generate_summary()

        # Save complete results
        results_file = self.output_dir / 'complete_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        # Generate HTML report
        html_report = await self.report_gen.generate_html_report(self.results)
        html_file = self.output_dir / 'security_report.html'
        with open(html_file, 'w') as f:
            f.write(html_report)

        console.print(f"[green]✓ Reports generated[/green]")
        console.print(f"  - JSON: {results_file}")
        console.print(f"  - HTML: {html_file}")

    def _generate_summary(self) -> Dict:
        """Generate scan summary"""
        summary = {
            'total_urls_crawled': len(self.results.get('crawled_urls', [])),
            'sql_injection_vulns': len([r for r in self.results.get('sql_injection', []) if r.get('vulnerable', False)]),
            'xss_vulns': len([r for r in self.results.get('xss', []) if r.get('vulnerable', False)]),
            'paths_discovered': len(self.results.get('path_enumeration', [])),
            'header_issues': len(self.results.get('header_analysis', {}).get('issues', [])),
            'risk_level': 'Low'  # Will be calculated based on findings
        }

        # Calculate overall risk level
        total_vulns = summary['sql_injection_vulns'] + summary['xss_vulns']
        if total_vulns > 5:
            summary['risk_level'] = 'High'
        elif total_vulns > 2:
            summary['risk_level'] = 'Medium'

        return summary

    def _save_intermediate_results(self, filename: str, data: any):
        """Save intermediate results to file"""
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 Web Scanner Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t https://example.com
  python main.py -t example.com -o /tmp/scan_results
  python main.py -t https://app.example.com -m crawler,filter,sql
  python main.py -t https://example.com -c config.json --check-tools
        """
    )

    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target URL or domain to scan'
    )

    parser.add_argument(
        '-o', '--output',
        default='results',
        help='Output directory for results (default: results)'
    )

    parser.add_argument(
        '-c', '--config',
        help='Configuration file path'
    )

    parser.add_argument(
        '-m', '--modules',
        help='Comma-separated list of modules to run (crawler,filter,sql,xss,paths,headers)'
    )

    parser.add_argument(
        '--check-tools',
        action='store_true',
        help='Check if required tools are installed'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check tools if requested
    if args.check_tools:
        tool_checker = ToolChecker()
        missing_tools = tool_checker.check_required_tools()

        if missing_tools:
            console.print("[red]✗ Missing required tools:[/red]")
            for tool in missing_tools:
                console.print(f"  - {tool}")
            console.print("\nPlease install missing tools before running the scanner.")
            sys.exit(1)
        else:
            console.print("[green]✓ All required tools are installed[/green]")
            return

    # Parse modules
    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(',')]

    # Validate target
    target = args.target
    if not target.startswith(('http://', 'https://')):
        # Try to determine if it's HTTPS
        if ':443' in target or target.endswith('.gov') or target.endswith('.mil'):
            target = f'https://{target}'
        else:
            target = f'http://{target}'

    try:
        # Initialize and run scanner
        scanner = OWASPScanner(target, args.output, args.config)
        results = await scanner.run_scan(modules)

        # Print final summary
        summary = results['summary']
        console.print(Panel.fit(
            f"[bold]Scan Summary[/bold]\n"
            f"URLs Crawled: {summary['total_urls_crawled']}\n"
            f"SQL Injection Vulnerabilities: {summary['sql_injection_vulns']}\n"
            f"XSS Vulnerabilities: {summary['xss_vulns']}\n"
            f"Paths Discovered: {summary['paths_discovered']}\n"
            f"Header Issues: {summary['header_issues']}\n"
            f"Overall Risk Level: [{'red' if summary['risk_level'] == 'High' else 'yellow' if summary['risk_level'] == 'Medium' else 'green'}]{summary['risk_level']}[/]",
            title="Scan Complete"
        ))

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("Error: Python 3.7+ is required")
        sys.exit(1)

    asyncio.run(main())