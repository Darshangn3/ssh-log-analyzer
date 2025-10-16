 SSH Log Analyzer

This Bash script automates the analysis of combined SSH authentication (au.log).  
It helps:

- Identify users who successfully logged in via SSH, along with client IP/port and server IP/port.
- Detect IP addresses with repeated failed login attempts that may indicate brute-force attacks.

Usage

1. Combine your SSH auth and network logs into one file.
2. Run the script and provide the full path to this combined log file.
3. Review the output for successful logins and suspicious failed attempts.

 Requirements

- Bash shell



