# Phishing Email Analyzer (Python)

A lightweight, dependency-free phishing email detection tool written in Python.
The analyzer uses heuristic-based scoring to evaluate both email language patterns
and embedded links for phishing indicators.

Designed to run cleanly on Linux environments (including Kali Linux).

## Features

- Regex-based link extraction
- HTTPS vs HTTP protocol inspection
- Suspicious file extension detection (.exe, .zip, .iso)
- Domain impersonation detection (brand abuse)
- Subdomain abuse detection
- Language heuristics:
  - Excessive urgency
  - Abnormal capitalization
  - Punctuation abuse
  - Informal salutations
- Explainable risk scoring

## How It Works

The analyzer assigns risk points based on multiple indicators.

### Language Analysis
- High urgency wording
- ALL CAPS abuse
- Excessive punctuation
- Informal or generic salutations

### Link Analysis
- Insecure protocols (http)
- Suspicious file extensions
- Double file extensions
- Excessive subdomains
- Brand impersonation (e.g. paypal-login-secure.com)

## Usage

```bash
python3 phish_analyzer.py
