# Evidence Directory

This directory contains forensic evidence collected during the Bruce Industries insider threat simulation. All files are organized by phase of the attack for easy reference.

## Directory Structure

```
evidence/
├── disk-imaging/          # Evidence acquisition and integrity verification
├── phishing/             # Social engineering artifacts
├── steganography/        # Data concealment evidence
├── exploitation/         # Web application and privilege escalation
└── exfiltration/         # Data theft and reconnaissance
```

## Evidence Files

### Disk Imaging
- **Disk_Imaging_Using_guymager.png** - Screenshot of forensic disk acquisition process
- **SHA-256_Hash_Verification.png** - Cryptographic hash verification for evidence integrity

### Phishing
- **Phishing_Email_from_Spoofed_Domain.png** - Initial coercive email from alerts@coinbbase.com
- **Follow-Up_Phishing_Email_with_Exploit_Instructions.png** - Second email with specific vulnerability instructions

### Steganography
- **Initial_Inspection_of_Image_File_Using_strings_Utility.png** - Discovery of hidden data using strings command
- **Extracted_Employee_Data_from_Steganographic_Image.png** - SPII data found embedded in Peter.png

### Exploitation
- **SQL_Injection_Attempt.png** - Wireshark capture of authentication bypass
- **Successful_Upload_of_a_PHP_Reverse_Shell.png** - RFI exploitation and shell upload
- **Wireshark_Capture_Showing_Privilege_Escalation_via_vim.png** - Sudo vim privilege escalation

### Exfiltration
- **Evidence_of_Remote_Root_Shell_Session.png** - Root shell access confirmation
- **Reconnaissance_in_the_HR_Manager_s_Directory.png** - Attacker browsing sensitive files
- **Exfiltrating_Data_Through_Python_Server.png** - Data theft via Python HTTP server

## Chain of Custody

All evidence was collected following proper forensic procedures:

1. **Acquisition**: Guymager used for bit-for-bit disk imaging
2. **Verification**: SHA-256 hashing to ensure integrity
3. **Analysis**: Autopsy and Wireshark for forensic examination
4. **Preservation**: Write-protected storage of original evidence
5. **Documentation**: Detailed notes and screenshots maintained

## Evidence Integrity

```
Evidence Image: victim_disk.E01
Hash Algorithm: SHA-256
Hash Value: 69812277979749dac854d2084a38e90a72b8b0754486590f2f1b6410eadd04b8
Acquisition Date: 2025-04-15
Examiner: Forensics Team
Case Number: BR-2025-001
```

## Usage Guidelines

These evidence files are for:
- Educational review of the forensic investigation
- Training incident response teams
- Understanding attack progression
- Learning forensic analysis techniques

**Note**: All sensitive data has been sanitized for publication. The employee SSNs and personal information shown are fictional and created solely for this simulation.

## Timeline Reference

For correlation with the attack timeline, see:
- [Attack Flow Diagram](../diagrams/attack_flow_diagram.png)
- [Detailed Forensic Report](../docs/DF_Project.pdf)
- [Lessons Learned](../docs/LESSONS_LEARNED.md)

## Forensic Tools Used

- **Guymager**: Disk imaging
- **Autopsy**: File system analysis
- **Wireshark**: Network traffic analysis
- **Strings**: Quick text extraction
- **Python**: Custom extraction scripts

## Questions?

For questions about evidence handling or analysis procedures, refer to the detailed forensic report in the `/docs` directory.
