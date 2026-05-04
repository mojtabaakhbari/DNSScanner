# DNS Scanner

An advanced asynchronous DNS scanner designed to find working DNS resolvers across various IP ranges. Built with performance and reliability in mind, featuring multiple IP generation strategies and real-time progress monitoring.

**Author: Mojtaba Akhbari**

## Features

- **High Performance**: Asynchronous scanning with configurable concurrency
- **Multiple IP Generation Strategies**: Random public IPs, custom IR IP ranges, leaked subnet scanning
- **Real-time UI**: Live progress monitoring with Rich console interface
- **Flexible Output**: Save results in text or JSON format
- **Smart IP Generation**: Heuristic-based IP selection for higher success rates
- **Comprehensive Logging**: Detailed success/failure tracking with latency measurements

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd "DNS Scanner Repo"
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python main.py -r 1000 -d google.com
```

This scans 1000 random public IPs for working DNS resolvers querying google.com.

### IP Generation Strategies

#### Random Public IPs

```bash
python main.py -r 5000
```

#### Custom Iranian IP Ranges (Full)

```bash
python main.py --cf 1000
```

#### Custom Iranian IP Ranges (Lite)

```bash
python main.py --cl 1000
```

#### Leaked Subnets

```bash
# Random IPs from leaked subnets
python main.py --ls 1000

# All IPs in leaked subnets
python main.py --al
```

#### From File

```bash
# Scan specific IPs/CIDRs from file
python main.py -f targets.txt

# Convert single IPs to /24 subnets
python main.py -f targets.txt --nearby
```

### Advanced Options

```bash
python main.py -r 1000 \
  -d example.com \
  -p 53 \
  --record A \
  --concurrency 500 \
  --timeout 3.0 \
  --tunnel \
  -o working_dns.txt \
  --json results.json
```

### Command Line Options

| Option                     | Description                                        |
| -------------------------- | -------------------------------------------------- |
| `-r, --random N`           | Scan N random public IPs                           |
| `--cf, --custom-full N`    | Scan N random IR IPs using custom first octet list |
| `--cl, --custom-lite N`    | Scan N random IR IPs using lite custom list        |
| `--ls, --leaked-subnets N` | Scan N random IPs from leaked subnets              |
| `--al, --all-leaked`       | Scan all IPs in leaked subnets                     |
| `-f, --file FILE`          | Read targets from file (IPs or CIDRs)              |
| `-d, --domain DOMAIN`      | Domain to query (default: google.com)              |
| `-p, --port PORT`          | Target UDP port (default: 53)                      |
| `--record TYPE`            | DNS record type (default: A)                       |
| `--nearby`                 | Convert single IPs in file to /24 subnets          |
| `--tunnel`                 | Simulate tunneling with encryption                 |
| `--concurrency N`          | Number of concurrent tasks (default: 200)          |
| `--timeout SECONDS`        | Query timeout (default: 5.0)                       |
| `-o, --output FILE`        | Save successful IPs to text file                   |
| `--json FILE`              | Save structured results to JSON file               |

## Output Files

- **working_dns.txt**: List of successful DNS resolver IPs
- **results.json**: Detailed results with latency measurements
- **fails_dns_resolver_TIMESTAMP.txt**: Failed attempts with error details

## Architecture

The scanner is organized into modular components:

- **core.py**: Main scanning logic and DNS worker implementation
- **ip_generator.py**: Various IP generation strategies
- **ui.py**: Real-time console interface using Rich
- **config.py**: Configuration constants and IP ranges
- **utils.py**: Helper functions and utilities

## IP Generation Strategies

### Heuristic-Based Generation

The scanner uses intelligent heuristics to generate IPs more likely to host DNS infrastructure:

- **Host Octet Bias**: Prioritizes common infrastructure numbers (1, 2, 5, 8, 9, 10, 53, 100, 253, 254)
- **Mid Octet Bias**: Targets common subnet boundaries and VLAN ranges
- **Geographic Targeting**: Custom ranges optimized for Iranian infrastructure

### Leaked Subnets

Includes comprehensive list of known Iranian ISP subnets for targeted scanning.

## Performance

- **Concurrency**: Automatically adjusts based on system limits
- **Memory Efficient**: Queue-based processing prevents memory overload
- **Graceful Shutdown**: Handles Ctrl+C and system signals properly
- **Error Recovery**: Robust error handling with detailed logging

## Requirements

- Python 3.7+
- dnspython
- rich
- uvloop (optional, for better performance)

See `requirements.txt` for complete dependency list.

## Examples

### Quick Scan

```bash
# Fast scan of 100 random IPs
python main.py -r 100 -d cloudflare.com
```

### Comprehensive Iranian Scan

```bash
# Full custom Iranian IP range scan
python main.py --cf 5000 -d iranicp.ir --concurrency 300
```

### File-Based Targeting

```bash
# Create targets.txt with IPs/CIDRs
echo "8.8.8.8" > targets.txt
echo "1.1.1.0/24" >> targets.txt

# Scan with enhanced logging
python main.py -f targets.txt --nearby -o dns_resolvers.txt
```

### High Performance Scan

```bash
# Maximum concurrency with short timeout
python main.py --al --concurrency 1000 --timeout 2.0 --json fast_results.json
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: May need to increase file descriptor limits
2. **Timeout Issues**: Reduce concurrency or increase timeout values
3. **Memory Usage**: Lower concurrency for systems with limited RAM

### Performance Tuning

- Start with `--concurrency 200` and adjust based on system performance
- Use `--timeout 3.0` for faster scans on reliable networks
- Enable `--tunnel` for testing DNS over encrypted connections

## License

This project is provided for educational and research purposes. Use responsibly and in accordance with applicable laws and network policies.

## Contributing

Contributions are welcome. Please ensure code follows the existing patterns and includes appropriate error handling.
