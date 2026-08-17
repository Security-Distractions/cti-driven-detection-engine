# Detection rules disabled 2026-08-17

All 21 were ES|QL rules failing on every execution with `verification_exception:
Unknown column [...]` — ES|QL validates field references against the index mappings
and errors hard when a field is absent, unlike KQL/EQL rules which simply match nothing.

## Re-enable when the domain controller joins (8)

These are genuine AD attack detections. They fail today only because no Windows host
is sending; once the DC is in Fleet and shipping winlog/powershell data, re-enable them
and confirm they run clean.

- Active Directory Forced Authentication from Linux Host - SMB Named Pipes
- Potential NTLM Relay Attack against a Computer Account
- Potential PowerShell Obfuscation via Special Character Overuse
- Temporarily Scheduled Task Creation
- A scheduled task was created
- Potential Kerberos Relay Attack against a Computer Account
- Remote Scheduled Task Creation via RPC
- Windows Service Installed via an Unusual Client

## No data source in this lab — leave disabled (13)

Okta, AWS CloudTrail, FortiGate, auditd, HTTP body capture, email, MSSQL, ML influencers,
and the Suricata correlation rule (Suricata was disabled 2026-08-11).

- FortiGate SOCKS Traffic from an Unusual Process
- Suricata and Elastic Defend Network Correlation
- Network Connection from Binary with RWX Memory Region
- Suspicious Passwd File Event Action
- AWS EC2 LOLBin Execution via SSM SendCommand
- Potential SQL Injection Against Microsoft SQL Server
- Anomalous React Server Components Flight Data Patterns
- Multiple Machine Learning Alerts by Influencer Field
- Okta Successful Login After Credential Attack
- React2Shell (CVE-2025-55182) Exploitation Attempt
- Elastic Defend and Email Alerts Correlation
- Stolen Credentials Used to Login to Okta Account After MFA Reset
- External Alerts
