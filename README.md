# 6NLG — Network Configuration Audit

## Description

Network Configuration Audit is a Python-based framework
for parsing, normalizing and auditing network device configurations.

Developed as part of a supervised engineering project at
SUP'COM in collaboration with 6NLG.

## Features

- Cisco IOS configuration parsing
- Juniper Junos configuration analysis
- Intermediate Representation (IR) normalization
- Static configuration security auditing
- CIS Cisco IOS 15 benchmark assessment
- 39 CIS security controls
- Flask web interface
- HTML and PDF report generation
- Configuration evidence extraction
- Automated tests and reference validation

## Architecture

```text
Network Configuration
        |
        v
     Parsing
        |
        v
  Normalization (IR)
        |
        v
   Audit Engine
        |
        v
   CIS Evaluation
        |
        v
 HTML / PDF Reports
```

## Technologies

- Python 3
- Flask
- JSON
- Cisco IOS
- Juniper Junos
- CiscoConfParse2
- CIS Benchmarks
- HTML / CSS
- Git / GitHub

## Installation

### 1. Clone the repository

```bash
git clone <REPOSITORY_URL>
cd 6NLG-Network-Config-Audit
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
```

```bash
python -m pip install flask jsonschema ciscoconfparse2
```

Install any additional dependencies documented by the project.

### 4. Configure Python imports

```bash
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/normalizers"
```

## Run the Application

```bash
python -m flask --app webapp.app run --host 127.0.0.1 --port 5000
```

Open:

http://127.0.0.1:5000

## Testing

### Python tests

```bash
python -m unittest discover -s tests -p "test_*.py" -q
```

### Flask tests

```bash
python -m unittest discover -s webapp/tests -p "test_*.py" -q
```

### CIS benchmark validation

```bash
python validation_reference_cis_39/run_validation.py .
```

## Latest Validated Results

- Python tests: 199 passed
- Flask tests: 37 passed
- CIS reference checks: 117/117
- CIS validation anomalies: 0

These results correspond to the validated local development environment.

## Security

- Static configuration analysis
- No automatic configuration changes to network devices
- Sensitive configuration data must not be committed
- Reports should redact credentials and secrets

## Project Team

- Mouhamed Amine Ouni
- Achref Mansouri

## Academic Institution

SUP'COM — Higher School of Communications of Tunis

## Professional Partner

6NLG

## Project Scope

Audit and Analysis of Router, Proxy and SD-WAN Configurations.
