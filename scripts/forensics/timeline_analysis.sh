#!/bin/bash
################################################################################
# Forensic Timeline Analysis Script
# Bruce Industries Simulation
#
# This script demonstrates basic forensic timeline analysis techniques
# used during the investigation.
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  Forensic Timeline Analysis Tool${NC}"
echo -e "${BLUE}  Bruce Industries Simulation Case Study${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""

# Check if running on actual Linux system
if [ ! -f "/var/log/auth.log" ] && [ ! -f "/var/log/secure" ]; then
    echo -e "${YELLOW}[!] Warning: This is a demonstration script${NC}"
    echo -e "${YELLOW}    No actual system logs found${NC}"
    echo -e "${YELLOW}    Showing example analysis from the simulation${NC}"
    echo ""
fi

################################################################################
# Function: Analyze Authentication Logs
################################################################################
analyze_auth_logs() {
    echo -e "${GREEN}[1] Authentication Log Analysis${NC}"
    echo "========================================"
    echo ""
    
    echo "In the Bruce Industries investigation, we analyzed /var/log/auth.log:"
    echo ""
    
    cat << 'EOF'
Example commands used:

# Find all sudo usage
grep "sudo" /var/log/auth.log | tail -20

# Focus on specific user (faraz)
grep "faraz" /var/log/auth.log | grep "sudo"

# Look for privilege escalation via vim
grep "vim" /var/log/auth.log | grep "COMMAND"

Key findings:
Apr 15 13:45:10 victim sudo: faraz : TTY=pts/1 ; PWD=/home/faraz ; 
  USER=root ; COMMAND=/usr/bin/cp /home/hrmanager/encrypted_data.tar.gz /home/faraz/

Apr 15 13:47:28 victim sudo: faraz : TTY=pts/1 ; PWD=/home/faraz ; 
  USER=root ; COMMAND=/usr/bin/cp /home/hrmanager/keys.txt /home/faraz/

Apr 15 14:35:21 victim sudo: daemon : TTY=pts/0 ; PWD=/home/daemon ; 
  USER=root ; COMMAND=/usr/bin/vim /home/hrmanager/root_access.txt

Analysis:
- User 'faraz' accessed HR manager's encrypted data
- Copied encryption keys to personal directory
- Later, user 'daemon' used vim with sudo (privilege escalation)
EOF
    
    echo ""
    echo -e "${GREEN}[+] Authentication analysis complete${NC}"
    echo ""
}

################################################################################
# Function: Analyze Bash History
################################################################################
analyze_bash_history() {
    echo -e "${GREEN}[2] Bash History Analysis${NC}"
    echo "========================================"
    echo ""
    
    echo "Examining /home/faraz/.bash_history revealed:"
    echo ""
    
    cat << 'EOF'
cd /home/hrmanager
ls -la
sudo cp encrypted_data.tar.gz /home/faraz/
cd
sudo cp /home/hrmanager/keys.txt .
cat keys.txt
openssl aes-256-cbc -d -in encrypted_data.tar.gz -out employee_data.csv -k $(cat keys.txt)
cat employee_data.csv
python3 steganography.py
ls -la Peter.png
strings Peter.png | head -20
rm employee_data.csv
rm keys.txt
history -c

Key observations:
1. Accessed HR directory
2. Copied encrypted data
3. Extracted encryption keys
4. Decrypted data using openssl
5. Ran steganography script
6. Verified hidden data with strings
7. COVERED TRACKS - deleted files and cleared history

Red flags:
- Accessing unauthorized directories
- Using steganography tools
- Attempting to hide activity (rm, history -c)
EOF
    
    echo ""
    echo -e "${GREEN}[+] Bash history analysis complete${NC}"
    echo ""
}

################################################################################
# Function: File System Timeline
################################################################################
analyze_file_timeline() {
    echo -e "${GREEN}[3] File System Timeline Analysis${NC}"
    echo "========================================"
    echo ""
    
    echo "Using Autopsy, we generated a timeline of file system events:"
    echo ""
    
    cat << 'EOF'
Autopsy Timeline Analysis:
-------------------------

Date/Time          | Activity | File Path
-------------------|----------|------------------------------------------
2025-04-15 13:45:12| M A C    | /home/hrmanager/encrypted_data.tar.gz
2025-04-15 13:45:15| M A C    | /home/faraz/encrypted_data.tar.gz
2025-04-15 13:47:30| M A C    | /home/faraz/keys.txt
2025-04-15 13:48:05| M A C    | /home/faraz/employee_data.csv
2025-04-15 13:52:18| M A C    | /home/faraz/steganography.py
2025-04-15 13:52:25| M A C    | /home/faraz/Peter.png
2025-04-15 13:53:10| .B.D     | /home/faraz/employee_data.csv (DELETED)
2025-04-15 13:53:15| .B.D     | /home/faraz/keys.txt (DELETED)

Legend:
M - Modified
A - Accessed  
C - Changed (metadata)
B - Backup time
D - Deleted

Analysis:
- Files moved from HR to personal directory
- Data decrypted (employee_data.csv created)
- Steganography performed
- Original files deleted to cover tracks
- BUT: Peter.png still contains hidden data!
EOF
    
    echo ""
    echo -e "${GREEN}[+] File timeline analysis complete${NC}"
    echo ""
}

################################################################################
# Function: Network Traffic Analysis
################################################################################
analyze_network_traffic() {
    echo -e "${GREEN}[4] Network Traffic Analysis (Wireshark)${NC}"
    echo "========================================"
    echo ""
    
    echo "PCAP analysis revealed the complete attack chain:"
    echo ""
    
    cat << 'EOF'
Wireshark Analysis Summary:
--------------------------

[Packet #144] SQL Injection
  POST /employee_pro/login.php
  Body: username=' OR '1'='1&password=' OR '1'='1
  Response: 200 OK (Authentication bypassed)

[Packet #203] RFI File Upload
  POST /employee_pro/upload.php
  Content-Type: multipart/form-data
  Uploaded: php-reverse-shell.php
  Response: "The file php-reverse-shell.php has been uploaded"

[Packet #206] Shell Activation
  GET /employee_pro/php-reverse-shell.php
  Result: Reverse connection established
  10.200.0.91:49712 -> 10.200.0.129:4444

[Packets #9210524-9210700] Privilege Escalation
  TCP Stream shows:
    $ id
    uid=33(www-data) gid=33(www-data)
    $ sudo -l
    User daemon may run: (ALL) NOPASSWD: /usr/bin/vim
    $ sudo vim
    [vim shell escape]
    # whoami
    root

[Packets #9358143-9362198] Data Exfiltration
  Python HTTP server started on port 9999
  GET /forensics_copy.tar.gz
  File size: 4.2MB
  Transfer complete

Filter Examples:
  http.request.method == "POST"
  tcp.port == 9999
  frame contains "forensics"
EOF
    
    echo ""
    echo -e "${GREEN}[+] Network traffic analysis complete${NC}"
    echo ""
}

################################################################################
# Function: Indicator of Compromise (IOC) Summary
################################################################################
generate_ioc_summary() {
    echo -e "${GREEN}[5] Indicators of Compromise (IOCs)${NC}"
    echo "========================================"
    echo ""
    
    cat << 'EOF'
Email IOCs:
-----------
From: alerts@coinbbase.com (typosquatted domain)
Subject: Security Alert: Unauthorized Transaction Detected
Domain: www.coinbbase.comsecurityalerts.com

File IOCs:
----------
File: Peter.png
Location: /home/faraz/
SHA-256: [Contains steganographic payload]
Hidden Data: Employee SSNs and SPII

File: php-reverse-shell.php
Location: /var/www/html/employee_pro/
Description: Web shell for remote access

File: forensics_copy.tar.gz
SHA-256: 69812277979749dac854d2084a38e90a72b8b0754486590f2f1b6410eadd04b8
Description: Exfiltrated HR data archive

Network IOCs:
-------------
Attacker IP: 10.200.0.129
Victim IP: 10.200.0.91
C2 Port: 4444/tcp (reverse shell)
Exfil Port: 9999/tcp (Python HTTP server)

Endpoints:
/employee_pro/login.php (SQL injection vulnerable)
/employee_pro/upload.php (RFI vulnerable)

System IOCs:
------------
Modified File: /etc/sudoers.d/daemon
Entry: daemon ALL=(ALL) NOPASSWD: /usr/bin/vim

Process: python3 -m http.server 9999
User: root (privilege escalation successful)

Behavioral IOCs:
----------------
- Unreported phishing email
- After-hours file access to HR directory
- Unusual sudo usage (daemon user)
- Steganography tool execution
- History clearing attempts
- File deletion to hide tracks
EOF
    
    echo ""
    echo -e "${GREEN}[+] IOC summary generated${NC}"
    echo ""
}

################################################################################
# Function: Generate Forensic Report Template
################################################################################
generate_report_template() {
    echo -e "${GREEN}[6] Generating Forensic Report Template${NC}"
    echo "========================================"
    echo ""
    
    cat << 'EOF' > /tmp/forensic_report_template.md
# Digital Forensic Investigation Report

## Case Information
- **Case Number**: BR-2025-001
- **Investigator**: [Name]
- **Date**: 2025-04-15
- **Evidence ID**: victim_disk.E01

## Executive Summary
[Brief overview of the incident and findings]

## Evidence Acquisition
- **Tool Used**: Guymager v0.8.13
- **Source Device**: /dev/sda
- **Hash Algorithm**: SHA-256
- **Hash Value**: [Insert hash]
- **Acquisition Date**: [Date/Time]

## Timeline of Events
| Time | Event | Evidence |
|------|-------|----------|
| 13:30:00 | Phishing email received | Email headers |
| ... | ... | ... |

## Findings
### 1. Initial Access
[Description]

### 2. Data Exfiltration
[Description]

### 3. Privilege Escalation
[Description]

## Indicators of Compromise
[List IOCs discovered]

## Conclusions
[Summary of findings and recommendations]

## Appendix
### A. Evidence Log
### B. Tool Output
### C. Screenshots
EOF
    
    echo -e "${YELLOW}[*] Report template created: /tmp/forensic_report_template.md${NC}"
    echo ""
    echo -e "${GREEN}[+] Report template generated${NC}"
    echo ""
}

################################################################################
# Main Execution
################################################################################
main() {
    echo -e "${YELLOW}[*] Running comprehensive forensic analysis...${NC}"
    echo ""
    
    analyze_auth_logs
    analyze_bash_history
    analyze_file_timeline
    analyze_network_traffic
    generate_ioc_summary
    generate_report_template
    
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${BLUE}  Analysis Complete${NC}"
    echo -e "${BLUE}======================================================================${NC}"
    echo ""
    echo -e "${GREEN}Summary:${NC}"
    echo "  ✓ Authentication logs analyzed"
    echo "  ✓ Bash history examined"
    echo "  ✓ File timeline reconstructed"
    echo "  ✓ Network traffic analyzed"
    echo "  ✓ IOCs identified"
    echo "  ✓ Report template generated"
    echo ""
    echo -e "${YELLOW}For complete analysis, see:${NC}"
    echo "  - Full Report: ../docs/DF_Project.pdf"
    echo "  - Presentation: ../docs/Digital_Forensics_Final_Project.pdf"
    echo "  - Lessons Learned: ../docs/LESSONS_LEARNED.md"
    echo ""
    echo -e "${BLUE}This demonstration script shows the forensic methodology used${NC}"
    echo -e "${BLUE}during the Bruce Industries insider threat investigation.${NC}"
    echo ""
}

# Run main function
main
