# SSH Authentication Log Analysis

A Python-based cybersecurity project that analyzes SSH authentication logs to detect suspicious login activity such as repeated authentication failures and potential brute-force attempts.

This project demonstrates how security analysts can investigate authentication logs to identify possible unauthorized access attempts.

## Project Overview

SSH servers generate authentication logs that contain valuable information about login attempts. These logs can reveal suspicious activity such as:

repeated failed login attempts

brute-force attacks

targeted usernames

suspicious remote hosts

This project parses authentication failure logs and generates a report highlighting potential security threats.

## Features

Parses SSH authentication logs

Extracts remote host and targeted username information

Identifies hosts with repeated login failures

Detects suspicious activity based on configurable thresholds

Generates investigation reports in multiple formats:

TXT

CSV

JSON

## Project Structure
```
ssh-auth-log-analysis
│
├── data
│   └── ssh_auth_sample.log
│
├── reports
│
├── src
│   └── auth_log_analyzer.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

Clone the repository:
```
git clone https://github.com/wivalconcept/ssh-auth-log-analysis.git
cd ssh-auth-log-analysis
```
## Installation

Install dependencies:

```bash
pip install -r requirements.txt
```
## Usage

Run the analyzer by specifying:

input log file

output report file

report format

## Example (text report):
```
python src/auth_log_analyzer.py -i data/ssh_auth_sample.log -o reports/report.txt -f txt
```
## Generate JSON report:
```
python src/auth_log_analyzer.py -i data/ssh_auth_sample.log -o reports/report.json -f json
```
## Generate CSV report:
```
python src/auth_log_analyzer.py -i data/ssh_auth_sample.log -o reports/report.csv -f csv
```
## Optional: adjust the suspicious activity threshold
```
python src/auth_log_analyzer.py -i data/ssh_auth_sample.log -o reports/report.txt -f txt -t 5
```
## Example Findings

The analyzer identifies:

total authentication failures

most active remote hosts attempting login

most targeted usernames

suspicious hosts with repeated failed login attempts

These insights help security analysts detect potential brute-force attacks or unauthorized access attempts.

## Skills Demonstrated

This project demonstrates practical cybersecurity and technical skills including:

Python scripting

Log analysis

Security event investigation

Threat detection

Data analysis with Pandas

Regular expressions for log parsing

## Future Improvements

Possible enhancements include:

visualization of attack patterns

geographic analysis of attacking IP addresses

real-time log monitoring

integration with SIEM tools

automated alert generation

Example Report Output


SSH Authentication Failure Report
============================================================

1. Executive Summary
------------------------------------------------------------
Total authentication failures: 181
Unique remote hosts: 20
Unique targeted users: 3
Suspicious hosts count: 18
Time range: 2025-06-14 15:16:01 to 2025-06-29 12:12:10

2. Top Remote Hosts
------------------------------------------------------------
                                   rhost  failed_attempts
            n219076184117.netvigator.com               23
                             218.188.2.4               14
             h64-187-1-131.gtconnect.net               13
                         209.152.168.249               10
            62-192-102-94.dsl.easynet.nl               10
adsl-70-242-75-179.dsl.ksc2mo.swbell.net               10



## Author

Cybersecurity professional transitioning from Data Analytics with a focus on security operations, threat detection, and log analysis.

## License

This project is for educational and portfolio purposes.
