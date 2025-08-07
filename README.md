# NETWORK-REACHABILITY-CHECKER(1) User Manual

## NAME
network-reachability-checker - check reachability of domains and IP addresses/ranges/CIDRs

## SYNOPSIS
**network-reachability-checker** [*OPTIONS*] {**--domain-file** *FILE* | **--ip** *SPEC* | **--ip-file** *FILE*} *OUTPUT_FILE*

## DESCRIPTION
**network-reachability-checker** is a comprehensive utility for testing the reachability of network targets including domain names, individual IP addresses, IP ranges, and CIDR blocks. The tool supports multiple testing methods, concurrent processing for high performance, and detailed reporting.

The tool can perform DNS resolution checks for domains, reverse DNS lookups, ICMP ping tests, and port scanning to determine if network targets are reachable.

## ARGUMENTS
**OUTPUT_FILE**
: Path to the output file where reachable targets will be saved. The format depends on the --metadata flag (simple list or CSV with details).

## TARGET SPECIFICATION
Exactly one of the following target specification options must be provided:

**--domain-file** *FILE*
: Path to file containing domain names, one per line. Supports comments (lines starting with #) and empty lines are ignored.

**--ip** *SPECIFICATION*
: Single IP address, IP range, or CIDR block specification. Supports multiple formats:
  - Single IP: `192.168.1.1`
  - Short range: `192.168.1.1-10` (expands to 192.168.1.1 through 192.168.1.10)
  - Full range: `192.168.1.1-192.168.1.20`
  - CIDR block: `192.168.1.0/24`

**--ip-file** *FILE*
: Path to file containing IP specifications (one per line). Each line can be any of the formats supported by --ip option.

## OPTIONS
**-m**, **--method** {dns,ping,port,all}
: Reachability testing method (default: dns)
  - **dns**: DNS resolution for domains, reverse DNS for IPs
  - **ping**: ICMP ping test (requires appropriate permissions)
  - **port**: TCP port scanning on common ports
  - **all**: Combines all three methods (slower but most thorough)

**-t**, **--timeout** *SECONDS*
: Network operation timeout in seconds (default: 5.0). Applies to DNS lookups, ping operations, and port connections.

**-w**, **--workers** *COUNT*
: Maximum number of concurrent worker threads (default: 50). Higher values can improve performance but may overwhelm network infrastructure. Valid range: 1-200.

**-r**, **--retries** *COUNT*
: Number of retries for failed network operations (default: 2). Does not apply to definitive failures like "domain not found".

**--only-reachable**
: Filter output to include only targets that were successfully reached. Unreachable targets will be excluded from the output file.

**--metadata**
: Include detailed metadata in the output file. Changes output format to CSV with columns: target, reachable, method, response_time, error.

**-v**, **--verbose**
: Enable verbose logging with detailed processing information, warnings, and debugging output.

**--version**
: Show program version and exit.

**-h**, **--help**
: Show help message and exit.

## TESTING METHODS
### DNS Method (default)
- **For domains**: Performs forward DNS lookup to resolve domain to IP address
- **For IPs**: Performs reverse DNS lookup to find hostname associated with IP
- **Pros**: Fast, reliable, works behind firewalls
- **Cons**: Only tests DNS infrastructure, not actual host reachability

### Ping Method
- **Operation**: Sends ICMP echo request packets to target
- **Pros**: Tests actual network connectivity to host
- **Cons**: May be blocked by firewalls, requires appropriate system permissions
- **Note**: On Windows, uses `ping -n 1 -w <timeout>`. On Unix systems, uses `ping -c 1 -W <timeout>`

### Port Method
- **Operation**: Attempts TCP connections to common ports (80, 443, 22, 21, 25, 53, 110, 143, 993, 995)
- **Pros**: Tests actual service availability, works when ping is blocked
- **Cons**: Slower than other methods, may trigger security alerts
- **Result**: Reports which ports (if any) are open and responding

### All Method
- **Operation**: Runs all three test methods and combines results
- **Result**: Target is considered reachable if ANY method succeeds
- **Use case**: Most thorough testing when you need maximum confidence

## INPUT FILE FORMATS
### Domain File Format
```
# List of domains to check
google.com
facebook.com
https://www.github.com
stackoverflow.com
# This domain will fail
nonexistent-domain-12345.com
```

### IP File Format
```
# Mixed IP specifications
8.8.8.8
192.168.1.1-10
10.0.0.0/24
172.16.0.1-172.16.0.100
# Comments are supported
```

## OUTPUT FORMATS
### Standard Output (default)
Simple list of reachable targets, one per line:
```
google.com
facebook.com
github.com
stackoverflow.com
```

### Metadata Output (--metadata flag)
CSV format with detailed information:
```
target,reachable,method,response_time,error
google.com,True,dns,0.123,
facebook.com,True,dns,0.089,
nonexistent.com,False,dns,5.002,dns_resolution_failed
github.com,True,dns,0.156,
```

## EXAMPLES
### Basic Domain Checking
```bash
# Check domains from file using DNS
network-reachability-checker --domain-file domains.txt reachable_domains.txt
```

### IP Range Testing with Ping
```bash
# Check local network range using ping
network-reachability-checker --ip 192.168.1.1-50 --method ping --timeout 2 local_hosts.txt
```

### Comprehensive Testing
```bash
# Test CIDR block with all methods and full metadata
network-reachability-checker --ip 10.0.0.0/24 --method all --metadata --workers 100 comprehensive_results.csv
```

### High-Performance Processing
```bash
# Process large IP file with optimized settings
network-reachability-checker --ip-file large_ip_list.txt --workers 150 --timeout 3 --only-reachable results.txt
```

### Verbose Domain Checking
```bash
# Check domains with detailed logging
network-reachability-checker --domain-file domains.txt --verbose --metadata --retries 3 detailed_results.csv
```

## PERFORMANCE CONSIDERATIONS
### Concurrency Settings
- **Conservative**: 10-25 workers for stable, respectful testing
- **Standard**: 50-75 workers (default: 50) for balanced performance
- **Aggressive**: 100-200 workers for maximum speed (may trigger rate limiting)

### Timeout Guidelines
- **Fast scanning**: 1-3 seconds (may miss slow targets)
- **Balanced**: 5 seconds (default, good accuracy/speed trade-off)
- **Thorough**: 8-15 seconds (catches slow targets, slower processing)

### Method Performance (approximate times per target)
- **DNS**: 0.1-1 second per target
- **Ping**: 0.5-5 seconds per target  
- **Port**: 2-10 seconds per target
- **All**: 3-15 seconds per target (sum of all methods)

### Large Dataset Recommendations
For very large IP ranges or CIDR blocks:
- Start with smaller worker counts to test network capacity
- Use shorter timeouts for initial broad scanning
- Consider splitting large ranges into smaller chunks
- Monitor system resources (network bandwidth, CPU, memory)

## ERROR HANDLING AND TROUBLESHOOTING
### Common Error Types
- **dns_resolution_failed**: Domain doesn't exist or DNS server unreachable
- **dns_timeout**: DNS query took longer than specified timeout
- **ping_failed**: ICMP ping received no response
- **ping_timeout**: Ping operation exceeded timeout
- **no_open_ports**: No TCP ports responded (port scan method)
- **invalid_ip_format**: IP address specification is malformed
- **invalid_domain_format**: Domain name format is invalid

### Permission Issues
- **Ping on Linux/macOS**: May require sudo for ICMP sockets
- **Ping alternative**: Use DNS or port methods if ping requires elevated privileges
- **Port scanning**: Some networks may block or throttle port scan attempts

### Performance Issues
- **Slow processing**: Reduce worker count, increase timeout, check network capacity
- **High CPU usage**: Reduce worker count
- **Memory usage**: For very large IP ranges, consider splitting input files
- **Network congestion**: Reduce concurrent workers, increase timeout

## EXIT STATUS
**0**
: Success - processing completed (some targets may have failed reachability tests)

**1**
: Error - file not found, permission denied, invalid arguments, or critical processing error

## STATISTICS AND REPORTING
The tool provides comprehensive statistics after processing:

```
✅ Network Reachability Summary:
   Total targets processed: 1000
   Reachable: 734 (73.4%)
   Unreachable: 266
   Invalid format: 5
   Processing errors: 3
   Processing time: 45.67 seconds
   Average time per target: 0.046 seconds
   Output saved to: results.txt
```

## SECURITY CONSIDERATIONS
- **Port scanning**: May trigger intrusion detection systems or security alerts
- **Rate limiting**: Excessive requests may be rate-limited by DNS servers or firewalls
- **Network policies**: Some networks block ICMP or have strict egress filtering
- **Responsible use**: Use appropriate delays and worker limits to avoid overwhelming targets

## DEPENDENCIES
### Required Python Packages
- Standard library modules: argparse, ipaddress, socket, subprocess, sys, time, logging, concurrent.futures, pathlib, typing, threading, platform
- **tqdm**: Progress bar display (`pip install tqdm`)

### System Requirements
- **Ping method**: Requires `ping` command available in system PATH
- **Network access**: Requires outbound network connectivity for testing
- **Permissions**: ICMP ping may require elevated privileges on some systems

## LIMITATIONS
- **IPv4 Only**: Currently only supports IPv4 addresses and networks
- **Single IP per domain**: Returns only the first resolved IP address for domains
- **No IPv6**: IPv6 addresses and networks are not supported
- **Platform dependencies**: Ping command syntax varies between operating systems
- **Firewall interference**: Results may vary based on local and remote firewall configurations

## FILES
### Temporary Files
No temporary files are created during operation.

### Log Files
When verbose mode is enabled, detailed logs are output to stderr.

## ENVIRONMENT
No special environment variables are required. The tool respects system network configuration and DNS settings.

## SEE ALSO
**ping(8)**, **dig(1)**, **nslookup(1)**, **nmap(1)**, **traceroute(8)**, **systemd-resolve(1)**

## AUTHOR
Written by [Your Name]

## COPYRIGHT
This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

## VERSION
Network Reachability Checker 2.0

---

## INSTALLATION
### System-wide Installation
```bash
# Make executable and install
chmod +x network-reachability-checker
sudo cp network-reachability-checker /usr/local/bin/

# Install man page
sudo cp network-reachability-checker.1 /usr/local/share/man/man1/
sudo mandb
```

### Dependencies Installation
```bash
# Install required Python package
pip install tqdm

# Verify ping command availability
ping -c 1 google.com  # Linux/macOS
ping -n 1 google.com  # Windows
```

## EXAMPLES BY USE CASE
### Network Discovery
```bash
# Discover active hosts in local network
network-reachability-checker --ip 192.168.1.0/24 --method ping --only-reachable active_hosts.txt
```

### Domain Validation
```bash
# Validate list of company domains
network-reachability-checker --domain-file company_domains.txt --metadata validation_results.csv
```

### Security Scanning
```bash
# Port scan specific range with detailed output
network-reachability-checker --ip 10.0.1.1-100 --method port --metadata --verbose scan_results.csv
```

### Bulk DNS Resolution
```bash
# Resolve large list of domains to IPs
network-reachability-checker --domain-file massive_domain_list.txt --workers 200 --only-reachable resolved_domains.txt
```
