# Bruce Industries: Insider Threat Forensics Simulation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Digital Forensics](https://img.shields.io/badge/Category-Digital%20Forensics-blue.svg)]()
[![Red Team](https://img.shields.io/badge/Type-Red%20Team%20Simulation-red.svg)]()

## 🎯 Project Overview

This repository documents a comprehensive **Red Team simulation** conducted to evaluate organizational incident response capabilities against a sophisticated insider threat scenario. The simulation involved a multi-stage attack combining social engineering (phishing), privilege escalation, steganography, and data exfiltration techniques.

**Simulated Company**: Bruce Industries - A globally recognized VLSI design and semiconductor manufacturing firm

**Attack Vector**: Coercion-based insider threat via phishing + technical exploitation

**Simulation Date**: April 15, 2025

---

## 🔍 Executive Summary

The simulation tested an organization's ability to detect and respond to a blended threat involving:
- **Social Engineering**: Typosquatted phishing emails impersonating Coinbase
- **Insider Manipulation**: Employee coerced into introducing vulnerabilities
- **Data Concealment**: Steganographic techniques to hide sensitive HR data
- **Privilege Escalation**: Exploited sudoers misconfiguration (vim NOPASSWD)
- **Web Application Attacks**: SQL Injection and Remote File Inclusion (RFI)
- **Data Exfiltration**: Covert channel via Python HTTP server

The forensic investigation successfully reconstructed the complete attack timeline using disk imaging, network traffic analysis, and system log examination.

---

## 🏗️ Attack Kill Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACK TIMELINE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [1] Initial Compromise                                             │
│      └─ Phishing email from alerts@coinbbase.com                    │
│         └─ Exposed crypto wallet private key                        │
│            └─ Threat: "2 BTC transferred - comply or lose more"     │
│                                                                     │
│  [2] Insider Coercion Phase                                         │
│      └─ Employee "faraz" accesses sensitive HR data                 │
│         └─ Data transferred to personal directory                   │
│            └─ Embedded in images using steganography                │
│                                                                     │
│  [3] Second Phishing Email                                          │
│      └─ Explicit instructions delivered                             │
│         └─ "Introduce RFI vulnerability into HR portal"             │
│            └─ "Ensure SQL injection is available"                   │
│               └─ "Modify sudoers for daemon NOPASSWD vim"           │
│                                                                     │
│  [4] Vulnerability Introduction                                     │
│      └─ Employee implements directed changes                        │
│         └─ SQL Injection added to /employee_pro/login.php           │
│            └─ RFI enabled in /employee_pro/upload.php               │
│               └─ sudoers: daemon ALL=(ALL) NOPASSWD: /usr/bin/vim   │
│                                                                     │
│  [5] External Exploitation                                          │
│      └─ Attacker exploits SQL injection                             │
│         └─ Uploads PHP reverse shell via RFI                        │
│            └─ Gains initial web shell access                        │
│                                                                     │
│  [6] Privilege Escalation                                           │
│      └─ Escalates from www-data to daemon user                      │
│         └─ Exploits vim sudo privilege                              │
│            └─ :!bash spawns root shell                              │
│               └─ Full system compromise achieved                    │
│                                                                     │
│  [7] Reconnaissance & Data Theft                                    │
│      └─ Explores /home/hrmanager directory                          │
│         └─ Identifies sensitive employee files                      │
│            └─ Extracts encryption keys                              │
│               └─ Decrypts archived HR data                          │
│                                                                     │
│  [8] Exfiltration                                                   │
│      └─ Sets up Python HTTP server on port 9999                     │
│         └─ Downloads compressed HR data                             │
│            └─ Mission complete: SPII exfiltrated                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

### Forensic Analysis Tools
- **Autopsy** - Disk image analysis and timeline reconstruction
- **The Sleuth Kit** - File system forensics
- **Wireshark** - Network traffic analysis and PCAP examination
- **Guymager** - Forensic disk imaging with integrity verification

### Attack Tools (Simulated)
- **SQLMap** - SQL injection exploitation
- **PHP Reverse Shell** - Remote command execution
- **Steganography** - Data concealment (steghide/custom Python)
- **Python HTTP Server** - Data exfiltration channel

### Security Infrastructure
- **TLS Interception** (SSL Proxy) - HTTPS traffic inspection
- **Decryption Keys** - Enabled forensic analysis of encrypted traffic

---

## 📁 Repository Structure

```
bruce-industries-forensics-simulation/
├── README.md                          # This file
├── docs/
│   ├── Digital_Forensics_Final_Project.pdf   # Presentation slides
│   ├── DF_Project.pdf                         # Detailed forensic report
│   └── LESSONS_LEARNED.md                     # Key takeaways
├── evidence/
│   ├── disk-imaging/
│   │   ├── Disk_Imaging_Using_guymager.png
│   │   └── SHA-256_Hash_Verification.png
│   ├── phishing/
│   │   ├── Phishing_Email_from_Spoofed_Domain.png
│   │   └── Follow-Up_Phishing_Email_with_Exploit_Instructions.png
│   ├── steganography/
│   │   ├── Initial_Inspection_of_Image_File_Using_strings_Utility.png
│   │   └── Extracted_Employee_Data_from_Steganographic_Image.png
│   ├── exploitation/
│   │   ├── SQL_Injection_Attempt.png
│   │   ├── Successful_Upload_of_a_PHP_Reverse_Shell.png
│   │   └── Wireshark_Capture_Showing_Privilege_Escalation_via_vim.png
│   └── exfiltration/
│       ├── Evidence_of_Remote_Root_Shell_Session.png
│       ├── Reconnaissance_in_the_HR_Manager_s_Directory.png
│       └── Exfiltrating_Data_Through_Python_Server.png
├── scripts/
│   ├── attack-simulation/
│   │   ├── sql_injection_payload.txt
│   │   ├── php_reverse_shell.php
│   │   └── privilege_escalation.sh
│   ├── steganography/
│   │   ├── embed_data.py
│   │   └── extract_data.py
│   └── forensics/
│       ├── timeline_analysis.sh
│       └── evidence_extractor.py
└── diagrams/
    ├── attack_flow_diagram.png
    ├── network_topology.png
    └── timeline_visualization.png
```

---

## 🔬 Key Findings

### 1. **Phishing Vector**
- **Source**: alerts@coinbbase.com (typosquatted domain)
- **Method**: Cryptocurrency wallet compromise threat
- **Impact**: Employee never reported the email → Critical failure point

### 2. **Steganographic Data Concealment**
- **Tool**: Python steganography script
- **File**: `Peter.png` in /home/faraz/
- **Hidden Data**: Employee SSNs and SPII
- **Detection**: Strings utility revealed embedded CSV data

### 3. **SQL Injection Exploitation**
```sql
username=' OR '1'='1&password=' OR '1'='1
```
- Bypassed authentication in `/employee_pro/login.php`
- Enabled database enumeration

### 4. **Remote File Inclusion (RFI)**
- Vulnerable endpoint: `/employee_pro/upload.php`
- Uploaded: `php-reverse-shell.php`
- Result: Initial foothold as www-data user

### 5. **Privilege Escalation via Vim**
```bash
# Sudoers misconfiguration
daemon ALL=(ALL) NOPASSWD: /usr/bin/vim

# Exploitation
sudo vim -c ':!bash'
```
- Escalated from daemon → root
- Full system compromise

### 6. **Data Exfiltration**
```bash
# Attacker's exfiltration server
python3 -m http.server 9999

# Downloaded files
forensics_copy.tar.gz (SHA-256: 69812277979749dac854d2084a38e90a72b8b0754486590f2f1b6410eadd04b8)
```

---

## 🎓 Learning Outcomes

### For Organizations
1. **Phishing Awareness**: Employees must report suspicious emails immediately
2. **TLS Interception**: Double-edged sword (security monitoring vs. privacy concerns)
3. **Least Privilege**: Avoid NOPASSWD sudoers entries
4. **Input Validation**: All user inputs must be sanitized (SQL injection prevention)
5. **Upload Restrictions**: File uploads require strict validation and sandboxing

### For Forensic Investigators
1. **Timeline Reconstruction**: Correlation of auth logs, bash history, and network traffic
2. **Steganography Detection**: Don't rely on file extensions; analyze file contents
3. **Evidence Preservation**: Proper chain of custody (Guymager → SHA-256 hashing)
4. **TLS Decryption**: Intercepted traffic provides invaluable visibility
5. **Behavioral Analysis**: User behavior changes indicate compromise

---

## 🚀 How to Use This Repository

### For Learning Digital Forensics
1. Review the [detailed forensic report](docs/DF_Project.pdf)
2. Examine evidence files in chronological order
3. Study the attack scripts to understand attacker methodology
4. Practice with the provided Python scripts (steganography tools)

### For Security Training
1. Use this as a Red Team exercise template
2. Adapt the scenario for your organization
3. Train incident response teams on similar threat patterns
4. Develop detection rules based on IOCs

### For Researchers
1. Analyze the forensic methodology
2. Improve detection techniques for steganography
3. Study insider threat behavioral patterns
4. Research TLS interception ethical considerations

---

## 🔐 Indicators of Compromise (IOCs)

### Email Indicators
- **From**: alerts@coinbbase.com (typosquatting)
- **Subject**: "Security Alert: Unauthorized Transaction Detected"
- **Malicious Domain**: www.coinbbase.comsecurityalerts.com

### File Indicators
```
SHA-256: 69812277979749dac854d2084a38e90a72b8b0754486590f2f1b6410eadd04b8
Filename: forensics_copy.tar.gz
Location: /home/hrmanager/

File: Peter.png (Steganographic container)
Hidden Data: Employee_ID,Full_Name,SSN
```

### Network Indicators
```
Attacker IP: 10.200.0.129
Target IP: 10.200.0.91
Exfiltration Port: 9999/tcp (Python HTTP Server)
SQL Injection Endpoint: /employee_pro/login.php
RFI Upload Endpoint: /employee_pro/upload.php
```

### System Indicators
```bash
# Sudoers modification
daemon ALL=(ALL) NOPASSWD: /usr/bin/vim

# Suspicious processes
python3 -m http.server 9999
/usr/bin/vim (run with sudo by daemon)

# Modified files
/employee_pro/login.php (SQL injection)
/employee_pro/upload.php (RFI vulnerability)
/etc/sudoers.d/daemon
```

---

## 📊 Forensic Methodology

### 1. Evidence Acquisition
```bash
# Disk imaging with Guymager
Source: /dev/sda (40GB VMware virtual disk)
Format: Expert Witness Format (.E01)
Hash Algorithm: SHA-256
Verification: Enabled (integrity check during acquisition)
```

### 2. Analysis Tools Workflow
```
Guymager → Disk Image → Autopsy
    ↓
Timeline Generation
    ↓
File System Analysis
    ↓
Keyword Searches
    ↓
Evidence Correlation
```

### 3. Network Traffic Analysis
```
Wireshark → PCAP Analysis → TLS Decryption
    ↓
HTTP Stream Reconstruction
    ↓
Protocol Analysis
    ↓
IOC Extraction
```

---

## ⚖️ Legal & Ethical Considerations

### Controlled Simulation
This was a **sanctioned Red Team exercise** conducted with:
- Executive approval (CISO authorization)
- Defined scope and rules of engagement
- No actual harm to individuals or systems
- Educational purpose for security team training

### TLS Interception Ethics
The simulation raised important questions:
- **Privacy vs. Security**: Balancing employee privacy with threat detection
- **Consent**: Was decryption of personal cryptocurrency communications ethical?
- **Disclosure**: The "penalty" (1 BTC seizure) highlighted real-world implications

### Real-World Application
In actual incidents, organizations must:
1. Obtain proper legal authorization before forensic analysis
2. Maintain chain of custody for evidence
3. Respect employee privacy rights
4. Follow incident response policies and procedures

---

## 📈 Impact & Results

### Detection Capabilities Tested
✅ **Successfully Detected**:
- Anomalous network traffic patterns
- Unauthorized file access
- Privilege escalation attempts
- Data exfiltration via unusual ports

❌ **Failed to Detect (Initially)**:
- Phishing email (never reported)
- Steganographic data hiding
- Gradual vulnerability introduction
- Insider behavioral changes

### Team Performance
- **Incident Response Time**: Immediate escalation after TLS alert
- **Forensic Analysis**: Complete timeline reconstruction achieved
- **Evidence Quality**: Chain of custody maintained throughout
- **Lessons Learned**: Comprehensive post-incident review conducted

---

## 🤝 Contributing

This repository serves as an educational resource. Contributions welcome:
- Additional forensic analysis techniques
- Improved detection methods
- Enhanced steganography detection scripts
- IOC enrichment and threat intelligence correlation

Please submit pull requests or open issues for discussion.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Forensic Tools**: Autopsy, The Sleuth Kit, Wireshark communities
- **Security Research**: MITRE ATT&CK framework for attack mapping
- **Educational Purpose**: This simulation was designed for security training and awareness

---

## 📞 Contact & Questions

For questions about the methodology or technical implementation:
- Open an issue in this repository
- Refer to the detailed documentation in `/docs`

---

## ⚠️ Disclaimer

This repository contains educational material about security vulnerabilities and attack techniques. The content should only be used for:
- **Authorized security testing** on systems you own or have explicit permission to test
- **Educational purposes** in controlled environments
- **Security research** with proper ethical guidelines

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before conducting security assessments.

---

**Project Date**: April 15, 2025  
**Last Updated**: January 2026  
**Status**: Completed ✅
