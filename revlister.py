#!/usr/bin/env python3
"""
Network Reachability Checker

A comprehensive utility for checking the reachability of domains and IP addresses.
Supports single IPs, IP ranges, CIDR blocks, and domain name resolution testing.
Features concurrent processing, multiple reachability test methods, and detailed reporting.

Features:
- Domain existence checking via DNS resolution
- IP reachability testing via multiple methods (reverse DNS, ping, port scan)
- Support for IP ranges and CIDR notation
- Concurrent processing for improved performance
- Comprehensive error handling and logging
- Flexible output formats and filtering options

Author: Your Name
Version: 2.0
License: MIT
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Union, Tuple, Optional, Set
from tqdm import tqdm
import threading
import platform


class NetworkReachabilityChecker:
    """
    A comprehensive network reachability checker supporting domains, IPs,
    ranges, and CIDR blocks with multiple testing methods and concurrent processing.
    """
    
    def __init__(self, timeout: float = 5.0, max_workers: int = 50, 
                 retry_count: int = 2, test_method: str = 'dns'):
        """
        Initialize the Network Reachability Checker.
        
        Args:
            timeout: Network operation timeout in seconds (default: 5.0)
            max_workers: Maximum concurrent threads (default: 50)
            retry_count: Number of retries for failed operations (default: 2)
            test_method: Reachability test method ('dns', 'ping', 'port', 'all')
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.retry_count = retry_count
        self.test_method = test_method
        
        # Statistics tracking
        self.stats = {
            'total_targets': 0,
            'reachable': 0,
            'unreachable': 0,
            'invalid_format': 0,
            'errors': 0
        }
        
        # Thread-safe lock for statistics
        self.stats_lock = threading.Lock()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Detect OS for ping command differences
        self.is_windows = platform.system().lower() == 'windows'
        
        # Common ports for port scanning method
        self.common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
    
    def validate_domain(self, domain: str) -> Tuple[str, bool]:
        """
        Validate and clean domain name format.
        
        Args:
            domain: Raw domain string
            
        Returns:
            Tuple of (cleaned_domain, is_valid)
        """
        if not domain or not isinstance(domain, str):
            return ('', False)
        
        # Clean the domain
        domain = domain.strip().lower()
        
        # Remove protocol prefixes
        for prefix in ['https://', 'http://', 'ftp://']:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove paths and parameters
        domain = domain.split('/')[0].split('?')[0]
        
        # Basic validation
        if not domain or '.' not in domain or len(domain) > 253:
            return (domain, False)
        
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            return (domain, False)
        
        return (domain, True)
    
    def domain_exists_dns(self, domain: str) -> Dict[str, Union[str, bool, float, List[str]]]:
        """
        Check domain existence using DNS resolution.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with test results including resolved IPs
        """
        start_time = time.time()
        result = {
            'target': domain,
            'method': 'dns',
            'reachable': False,
            'response_time': 0.0,
            'resolved_ips': [],
            'error': None
        }
        
        cleaned_domain, is_valid = self.validate_domain(domain)
        if not is_valid:
            result['error'] = 'invalid_domain_format'
            result['response_time'] = time.time() - start_time
            return result
        
        for attempt in range(self.retry_count + 1):
            try:
                # Set socket timeout
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.timeout)
                
                # Perform DNS lookup
                ip = socket.gethostbyname(cleaned_domain)
                result['resolved_ips'] = [ip]
                result['reachable'] = True
                result['response_time'] = time.time() - start_time
                
                socket.setdefaulttimeout(old_timeout)
                return result
                
            except socket.gaierror as e:
                result['error'] = f'dns_resolution_failed: {e}'
                socket.setdefaulttimeout(old_timeout)
                break  # DNS failure is definitive, don't retry
                
            except socket.timeout:
                socket.setdefaulttimeout(old_timeout)
                if attempt < self.retry_count:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                result['error'] = 'dns_timeout'
                break
                
            except Exception as e:
                socket.setdefaulttimeout(old_timeout)
                result['error'] = f'unexpected_error: {e}'
                break
        
        result['response_time'] = time.time() - start_time
        return result
    
    def ip_reachable_dns(self, ip: str) -> Dict[str, Union[str, bool, float, List[str]]]:
        """
        Check IP reachability using reverse DNS lookup.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with test results
        """
        start_time = time.time()
        result = {
            'target': ip,
            'method': 'reverse_dns',
            'reachable': False,
            'response_time': 0.0,
            'hostname': None,
            'error': None
        }
        
        for attempt in range(self.retry_count + 1):
            try:
                # Set socket timeout
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.timeout)
                
                # Perform reverse DNS lookup
                hostname, _, _ = socket.gethostbyaddr(ip)
                result['hostname'] = hostname
                result['reachable'] = True
                result['response_time'] = time.time() - start_time
                
                socket.setdefaulttimeout(old_timeout)
                return result
                
            except socket.herror:
                socket.setdefaulttimeout(old_timeout)
                result['error'] = 'no_reverse_dns_record'
                break  # No reverse DNS is definitive
                
            except socket.timeout:
                socket.setdefaulttimeout(old_timeout)
                if attempt < self.retry_count:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                result['error'] = 'reverse_dns_timeout'
                break
                
            except Exception as e:
                socket.setdefaulttimeout(old_timeout)
                result['error'] = f'unexpected_error: {e}'
                break
        
        result['response_time'] = time.time() - start_time
        return result
    
    def ip_reachable_ping(self, ip: str) -> Dict[str, Union[str, bool, float]]:
        """
        Check IP reachability using ICMP ping.
        
        Args:
            ip: IP address to ping
            
        Returns:
            Dictionary with ping results
        """
        start_time = time.time()
        result = {
            'target': ip,
            'method': 'ping',
            'reachable': False,
            'response_time': 0.0,
            'error': None
        }
        
        try:
            # Construct ping command based on OS
            if self.is_windows:
                cmd = ['ping', '-n', '1', '-w', str(int(self.timeout * 1000)), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(int(self.timeout)), ip]
            
            # Execute ping command
            process = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout + 2
            )
            
            if process.returncode == 0:
                result['reachable'] = True
            else:
                result['error'] = 'ping_failed'
                
        except subprocess.TimeoutExpired:
            result['error'] = 'ping_timeout'
        except FileNotFoundError:
            result['error'] = 'ping_command_not_found'
        except Exception as e:
            result['error'] = f'ping_error: {e}'
        
        result['response_time'] = time.time() - start_time
        return result
    
    def ip_reachable_port_scan(self, ip: str) -> Dict[str, Union[str, bool, float, List[int]]]:
        """
        Check IP reachability by scanning common ports.
        
        Args:
            ip: IP address to scan
            
        Returns:
            Dictionary with port scan results
        """
        start_time = time.time()
        result = {
            'target': ip,
            'method': 'port_scan',
            'reachable': False,
            'response_time': 0.0,
            'open_ports': [],
            'error': None
        }
        
        try:
            open_ports = []
            
            for port in self.common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout / len(self.common_ports))
                    
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                    
                    sock.close()
                    
                except Exception:
                    continue  # Skip this port and continue
            
            if open_ports:
                result['reachable'] = True
                result['open_ports'] = open_ports
            else:
                result['error'] = 'no_open_ports'
                
        except Exception as e:
            result['error'] = f'port_scan_error: {e}'
        
        result['response_time'] = time.time() - start_time
        return result
    
    def test_ip_reachability(self, ip: str) -> Dict[str, Union[str, bool, float, List]]:
        """
        Test IP reachability using the specified method(s).
        
        Args:
            ip: IP address to test
            
        Returns:
            Dictionary with comprehensive test results
        """
        # Validate IP address format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                'target': ip,
                'method': self.test_method,
                'reachable': False,
                'response_time': 0.0,
                'error': 'invalid_ip_format'
            }
        
        if self.test_method == 'dns':
            return self.ip_reachable_dns(ip)
        elif self.test_method == 'ping':
            return self.ip_reachable_ping(ip)
        elif self.test_method == 'port':
            return self.ip_reachable_port_scan(ip)
        elif self.test_method == 'all':
            # Test using all methods and combine results
            results = {
                'target': ip,
                'method': 'combined',
                'reachable': False,
                'response_time': 0.0,
                'tests': {}
            }
            
            # Run all test methods
            dns_result = self.ip_reachable_dns(ip)
            ping_result = self.ip_reachable_ping(ip)
            port_result = self.ip_reachable_port_scan(ip)
            
            results['tests']['dns'] = dns_result
            results['tests']['ping'] = ping_result
            results['tests']['port'] = port_result
            
            # IP is reachable if any method succeeds
            results['reachable'] = any([
                dns_result['reachable'],
                ping_result['reachable'],
                port_result['reachable']
            ])
            
            # Total response time is sum of all methods
            results['response_time'] = (
                dns_result['response_time'] +
                ping_result['response_time'] +
                port_result['response_time']
            )
            
            return results
        
        return {'error': f'unknown_test_method: {self.test_method}'}
    
    def expand_ip_range(self, ip_input: str) -> List[str]:
        """
        Expand IP input (single IP, range, or CIDR) into list of IP addresses.
        
        Args:
            ip_input: IP specification (e.g., "192.168.1.1", "192.168.1.1-10", "192.168.1.0/24")
            
        Returns:
            List of individual IP addresses
            
        Examples:
            >>> checker = NetworkReachabilityChecker()
            >>> checker.expand_ip_range("192.168.1.1-3")
            ['192.168.1.1', '192.168.1.2', '192.168.1.3']
            >>> checker.expand_ip_range("192.168.1.0/30")
            ['192.168.1.1', '192.168.1.2']
        """
        ips = []
        ip_input = ip_input.strip()
        
        try:
            # Try CIDR notation first
            if '/' in ip_input:
                network = ipaddress.ip_network(ip_input, strict=False)
                # For large networks, warn about potential performance impact
                if network.num_addresses > 1000:
                    self.logger.warning(
                        f"Large CIDR block {ip_input} contains {network.num_addresses} addresses. "
                        "This may take significant time to process."
                    )
                ips.extend([str(ip) for ip in network.hosts()])
                
            # Try IP range notation (e.g., 192.168.1.1-10 or 192.168.1.1-192.168.1.10)
            elif '-' in ip_input:
                parts = ip_input.split('-')
                if len(parts) == 2:
                    start_str, end_str = parts[0].strip(), parts[1].strip()
                    
                    # Handle short form (192.168.1.1-10)
                    if '.' not in end_str:
                        base_ip = '.'.join(start_str.split('.')[:-1])
                        end_str = f"{base_ip}.{end_str}"
                    
                    start_ip = ipaddress.ip_address(start_str)
                    end_ip = ipaddress.ip_address(end_str)
                    
                    if start_ip > end_ip:
                        self.logger.error(f"Invalid range: start IP {start_ip} > end IP {end_ip}")
                        return []
                    
                    # Warn about large ranges
                    range_size = int(end_ip) - int(start_ip) + 1
                    if range_size > 1000:
                        self.logger.warning(
                            f"Large IP range {ip_input} contains {range_size} addresses. "
                            "This may take significant time to process."
                        )
                    
                    current_ip = start_ip
                    while current_ip <= end_ip:
                        ips.append(str(current_ip))
                        current_ip += 1
                else:
                    raise ValueError(f"Invalid range format: {ip_input}")
                    
            # Single IP address
            else:
                ipaddress.ip_address(ip_input)  # Validate format
                ips.append(ip_input)
                
        except ValueError as e:
            self.logger.error(f"Invalid IP specification '{ip_input}': {e}")
            with self.stats_lock:
                self.stats['invalid_format'] += 1
        
        return ips
    
    def load_targets_from_file(self, file_path: Path, target_type: str) -> List[str]:
        """
        Load targets (domains or IP specifications) from file.
        
        Args:
            file_path: Path to input file
            target_type: Type of targets ('domain' or 'ip')
            
        Returns:
            List of targets loaded from file
        """
        targets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    if target_type == 'ip':
                        # For IP files, expand ranges/CIDR immediately
                        expanded_ips = self.expand_ip_range(line)
                        if not expanded_ips:
                            self.logger.warning(f"Line {line_num}: Invalid IP specification: {line}")
                        targets.extend(expanded_ips)
                    else:
                        # For domain files, just add the domain
                        targets.append(line)
            
            self.logger.info(f"Loaded {len(targets)} targets from {file_path}")
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file '{file_path}' not found")
        except PermissionError:
            raise PermissionError(f"Permission denied reading '{file_path}'")
        except Exception as e:
            raise Exception(f"Error reading file '{file_path}': {e}")
        
        return targets
    
    def process_targets_concurrent(self, targets: List[str], target_type: str) -> List[Dict]:
        """
        Process targets concurrently for improved performance.
        
        Args:
            targets: List of targets to process
            target_type: Type of targets ('domain' or 'ip')
            
        Returns:
            List of test results
        """
        results = []
        
        if not targets:
            self.logger.warning("No targets to process")
            return results
        
        # Update total targets count
        with self.stats_lock:
            self.stats['total_targets'] = len(targets)
        
        # Process targets concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks based on target type
            if target_type == 'domain':
                future_to_target = {
                    executor.submit(self.domain_exists_dns, target): target 
                    for target in targets
                }
            else:  # ip
                future_to_target = {
                    executor.submit(self.test_ip_reachability, target): target 
                    for target in targets
                }
            
            # Process results as they complete
            with tqdm(total=len(targets), desc=f"Testing {target_type}s", unit=target_type) as pbar:
                for future in as_completed(future_to_target):
                    try:
                        result = future.result()
                        results.append(result)
                        
                        # Update statistics
                        with self.stats_lock:
                            if result.get('reachable', False):
                                self.stats['reachable'] += 1
                            else:
                                self.stats['unreachable'] += 1
                                
                    except Exception as e:
                        self.logger.error(f"Error processing target: {e}")
                        with self.stats_lock:
                            self.stats['errors'] += 1
                    
                    pbar.update(1)
        
        return results
    
    def save_results(self, results: List[Dict], output_file: Path, 
                    only_reachable: bool = False, include_metadata: bool = False) -> None:
        """
        Save results to output file.
        
        Args:
            results: List of test results
            output_file: Path to output file
            only_reachable: If True, only save reachable targets
            include_metadata: If True, include detailed metadata
        """
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for result in results:
                    # Filter by reachability if requested
                    if only_reachable and not result.get('reachable', False):
                        continue
                    
                    # Write basic target information
                    target = result.get('target', 'unknown')
                    
                    if include_metadata:
                        # Include detailed metadata
                        reachable = result.get('reachable', False)
                        method = result.get('method', 'unknown')
                        response_time = result.get('response_time', 0.0)
                        error = result.get('error', '')
                        
                        f.write(f"{target},{reachable},{method},{response_time:.3f},{error}\n")
                    else:
                        # Simple format - just the target
                        f.write(f"{target}\n")
            
            filtered_count = len([r for r in results if not only_reachable or r.get('reachable', False)])
            self.logger.info(f"Saved {filtered_count} results to {output_file}")
            
        except Exception as e:
            raise Exception(f"Failed to save results to '{output_file}': {e}")
    
    def print_summary_statistics(self, processing_time: float) -> None:
        """Print detailed summary statistics."""
        total = self.stats['total_targets']
        reachable = self.stats['reachable']
        unreachable = self.stats['unreachable']
        
        if total == 0:
            print("❌ No targets were processed")
            return
        
        success_rate = (reachable / total) * 100 if total > 0 else 0
        
        print(f"\n✅ Network Reachability Summary:")
        print(f"   Total targets processed: {total}")
        print(f"   Reachable: {reachable} ({success_rate:.1f}%)")
        print(f"   Unreachable: {unreachable}")
        print(f"   Invalid format: {self.stats['invalid_format']}")
        print(f"   Processing errors: {self.stats['errors']}")
        print(f"   Processing time: {processing_time:.2f} seconds")
        print(f"   Average time per target: {processing_time/total:.3f} seconds")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Check reachability of domains and IP addresses/ranges/CIDRs",
        epilog="""
Examples:
  # Check domains from file
  %(prog)s --domain-file domains.txt reachable_domains.txt
  
  # Check single IP with ping
  %(prog)s --ip 8.8.8.8 --method ping results.txt
  
  # Check IP range with all methods
  %(prog)s --ip 192.168.1.1-10 --method all --metadata results.csv
  
  # Check CIDR block with custom settings
  %(prog)s --ip 10.0.0.0/24 --workers 100 --timeout 2 results.txt

IP formats supported:
  Single IP: 192.168.1.1
  Range: 192.168.1.1-10 or 192.168.1.1-192.168.1.10  
  CIDR: 192.168.1.0/24
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target specification (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--domain-file",
        type=Path,
        help="File containing domain names (one per line)"
    )
    group.add_argument(
        "--ip",
        type=str,
        help="Single IP, range (1.1.1.1-10), or CIDR (1.1.1.0/24)"
    )
    group.add_argument(
        "--ip-file",
        type=Path,
        help="File containing IP addresses/ranges/CIDRs (one per line)"
    )
    
    # Output file
    parser.add_argument(
        "output_file",
        type=Path,
        help="Output file for reachable targets"
    )
    
    # Testing method options
    parser.add_argument(
        "-m", "--method",
        choices=['dns', 'ping', 'port', 'all'],
        default='dns',
        help="Reachability test method (default: dns)"
    )
    
    # Performance options
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Network operation timeout in seconds (default: 5.0)"
    )
    
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=50,
        help="Maximum concurrent workers (default: 50)"
    )
    
    parser.add_argument(
        "-r", "--retries",
        type=int,
        default=2,
        help="Number of retries for failed operations (default: 2)"
    )
    
    # Output options
    parser.add_argument(
        "--only-reachable",
        action="store_true",
        help="Only save reachable targets to output file"
    )
    
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Include metadata in output (CSV format)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Network Reachability Checker 2.0"
    )
    
    return parser


def main() -> None:
    """Main entry point for the network reachability checker."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate arguments
    if args.timeout <= 0:
        print("❌ Timeout must be positive")
        sys.exit(1)
    
    if args.workers <= 0 or args.workers > 200:
        print("❌ Workers must be between 1 and 200")
        sys.exit(1)
    
    # Initialize checker
    checker = NetworkReachabilityChecker(
        timeout=args.timeout,
        max_workers=args.workers,
        retry_count=args.retries,
        test_method=args.method
    )
    
    try:
        start_time = time.time()
        
        # Process based on input type
        if args.domain_file:
            # Process domains from file
            if not args.domain_file.exists():
                print(f"❌ Domain file '{args.domain_file}' not found")
                sys.exit(1)
            
            domains = checker.load_targets_from_file(args.domain_file, 'domain')
            results = checker.process_targets_concurrent(domains, 'domain')
            
        elif args.ip:
            # Process single IP/range/CIDR
            ips = checker.expand_ip_range(args.ip)
            if not ips:
                print(f"❌ Invalid IP specification: {args.ip}")
                sys.exit(1)
            results = checker.process_targets_concurrent(ips, 'ip')
            
        elif args.ip_file:
            # Process IPs from file
            if not args.ip_file.exists():
                print(f"❌ IP file '{args.ip_file}' not found")
                sys.exit(1)
            
            ips = checker.load_targets_from_file(args.ip_file, 'ip')
            results = checker.process_targets_concurrent(ips, 'ip')
        
        # Save results
        checker.save_results(
            results, 
            args.output_file, 
            only_reachable=args.only_reachable,
            include_metadata=args.metadata
        )
        
        # Print summary
        end_time = time.time()
        checker.print_summary_statistics(end_time - start_time)
        print(f"   Output saved to: {args.output_file}")
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
