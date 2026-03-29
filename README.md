# Threat Intelligence Integration in Splunk SIEM

A university cybersecurity project that demonstrates how external threat intelligence can be integrated into Splunk SIEM to improve the detection of malicious activity. The project focuses on collecting Indicators of Compromise (IOCs), organizing and enriching them, generating realistic simulated logs, importing IOC data into Splunk as lookup tables, and creating correlation rules that automatically detect suspicious matches.

## Project Idea

Security teams deal with a huge amount of logs every day, and manually reviewing all of them is difficult and time-consuming. A SIEM platform such as Splunk helps by collecting security data in one place and making it searchable and monitorable.

This project extends that idea by integrating threat intelligence into Splunk. Instead of only storing logs, the system compares incoming events against known malicious indicators such as IP addresses, domains, URLs, and file hashes. When a match is found, Splunk can generate an alert for further investigation.

The project was built as a beginner-friendly practical workflow that shows how threat intelligence can be collected, processed, tested, and used in a small SOC-style lab environment.

## Main Objectives

The project was designed to achieve the following goals:

- Collect threat intelligence indicators from AlienVault OTX
- Organize and categorize the IOC data
- Generate simulated network and security logs for testing
- Import IOC datasets into Splunk as lookup tables
- Build correlation searches that match logs against known indicators
- Trigger alerts when malicious indicators appear in the logs
- Compare normal IOC lookups against an enhanced IOC dataset

## Technologies and Tools Used

- Splunk Enterprise
- AlienVault OTX
- Python
- Pandas
- NumPy
- Requests

## Project Workflow

The full workflow of the project is as follows:

1. Collect IOCs from AlienVault OTX using Python
2. Save the collected IOC data into CSV files
3. Clean and organize the indicator data by type
4. Generate synthetic security logs containing both benign and malicious events
5. Import IOC files into Splunk as lookup tables
6. Ingest the generated logs into Splunk
7. Create correlation searches for different IOC types
8. Trigger alerts whenever a log matches a known indicator
9. Compare detection performance between the regular IOC dataset and the enhanced IOC dataset

## Repository Structure

```text
Threat-Intelligence-Integration-in-Splunk-SIEM/
├── README.md
├── SOC-report.pdf
├── SOC-presentation.pdf
├── threat-intel.py
├── generated-logs.py
├── ioc_finished.csv
└── otx_generated_iocs_YYYYMMDD.csv
