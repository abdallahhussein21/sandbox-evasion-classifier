# Sandbox Evasion Technique Classifier

A multi-sandbox dynamic analysis framework using CAPE Sandbox v2.5 
to classify evasion techniques across multiple malware families.

## Tools & Technologies
- CAPE Sandbox v2.5
- Python 3.12
- VirtualBox 7.0
- MongoDB 7.0
- Kali Linux / Ubuntu 24.04

## What it does
Executes 3 malware families (Rombertik, Emotet, AgentTesla) across 
7 sandbox configurations with varied hardware settings. A custom Python 
differential analyzer compares API call sets and CAPE signatures across 
runs to detect evasion-triggered behavioral differences.

## Results
- 18 distinct evasion techniques classified
- 3 malware families analyzed
- 7 controlled analysis runs
- Evasion taxonomy mapped to academic classifications (Sandprint, Egele et al.)
