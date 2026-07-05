# JLFuxx — Advanced Web Fuzzer

> by **jakeloai**

A professional-grade web fuzzing tool with statistical baseline calibration, soft-404 detection, WAF evasion, and recursive directory brute-forcing.

Built for precision over noise.

---

## Installation

### Option 1: `go install` (Recommended)

```bash
go install github.com/jakeloai/jfuxx/cmd/jlfuxx@latest
```

Then run from anywhere:
```bash
jlfuxx -h
```

### Option 2: Build from source

```bash
git clone https://github.com/jakeloai/JLFuxx.git
cd jlfuxx
make install
```

This compiles and copies the binary to `/usr/local/bin`.

### Option 3: Manual build

```bash
go build -ldflags="-s -w" -o jlfuxx ./cmd/jfuxx
sudo mv jfuxx /usr/local/bin/
```

---

## Quick Start

```bash
# Basic directory brute
jlfuxx -r request.txt -w wordlist.txt -u http://target.com

# With soft-404 detection and recursion
jlfuxx -r req.txt -w dirs.txt -u http://target.com -recursion -recursion-depth 2 -soft404 -acc

# Time-based blind detection
jlfuxx -r req.txt -w sqli.txt -u http://target.com -cal-rounds 15 -threshold 1.5 -mt 1000

# Aggressive WAF evasion
jlfuxx -r req.txt -w payloads.txt -u http://target.com -evasion 2 -enc url|base64 -http2
```

---

## Key Features

- **Statistical Baseline**: IQR outlier rejection, Z-score anomaly detection
- **Soft-404 Detection**: Jaccard similarity-based per-directory learning
- **WAF Evasion**: 2 levels of realistic header chains and decoy headers
- **Recursive Scanning**: True directory recursion with deduplication
- **Chained Encoding**: `url|base64|hex` pipeline support
- **Graceful Shutdown**: Ctrl+C handling with context cancellation
- **Multiple Output**: JSON, CSV, HTML, Markdown + curl replay scripts

---

## License

MIT © jakeloai
