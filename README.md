# Cybersecurity File Scanner

This project focuses on the development and functionality of a **cybersecurity application** built in **Python**, using the **VirusTotal API** to analyze files for malicious content. The primary goal is to help users detect infected files by comparing their **hash values** against a global antivirus database.

## Purpose
To provide a tool that allows users to quickly scan files, identify potential threats, and automatically quarantine dangerous files, while keeping a history of all scans performed.

## Key Features
- File scanning through VirusTotal API
- Automatic SHA-256 hash calculation
- Automatic quarantine of malicious files
- Warning system for suspicious file types
- Persistent scan history saved to file
- Graphical User Interface using Tkinter

## Supported File Types
Currently, the application **scans only text files**. Support for additional file types such as `.exe`, `.bat`, `.sh`, `.pdf`, and others is **planned for future versions**.

## Requirements
- Python 3.x installed
- VirusTotal API Key (obtain from [virustotal.com](https://www.virustotal.com))
- Required Python libraries: `requests`, `tkinter`, `PIL` (Pillow)

To install Pillow:
```bash
pip install pillow
```

## How to Use
1. Launch the application.
2. Enter your VirusTotal API Key.
3. Select a file to scan.
4. The application will display scan results, including detection ratio.
5. If the file is malicious, it will be moved to a **Quarantine** folder.
6. Previous scan results can be viewed from the scan history section.

## Disclaimer
This tool is for **educational purposes only** and does not guarantee complete protection. It is intended to assist users in performing preliminary analysis of files for potential threats.
