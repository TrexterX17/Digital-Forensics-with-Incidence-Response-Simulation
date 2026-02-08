#!/bin/bash
################################################################################
# Privilege Escalation via Vim Sudo Misconfiguration
# Bruce Industries Forensics Simulation
#
# ⚠️  WARNING: FOR EDUCATIONAL PURPOSES ONLY
# This script demonstrates the privilege escalation technique exploited
# during the simulation. Use ONLY in authorized testing environments.
#
# Unauthorized system access is ILLEGAL.
################################################################################

# ANSI color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "======================================================================="
echo "  Privilege Escalation Demonstration: Vim Sudo Misconfiguration"
echo "  Bruce Industries Simulation Case Study"
echo "======================================================================="
echo -e "${NC}"

################################################################################
# VULNERABILITY ANALYSIS
################################################################################
echo -e "${YELLOW}[*] Analyzing sudoers configuration...${NC}"

# Check if current user has suspicious sudo permissions
SUDO_CHECK=$(sudo -l 2>/dev/null | grep -i "NOPASSWD")

if [ -z "$SUDO_CHECK" ]; then
    echo -e "${RED}[!] No NOPASSWD sudo permissions found for current user${NC}"
    echo -e "${YELLOW}[*] This demonstration requires the following sudoers entry:${NC}"
    echo -e "${GREEN}    daemon ALL=(ALL) NOPASSWD: /usr/bin/vim${NC}"
    exit 1
else
    echo -e "${GREEN}[+] Found NOPASSWD sudo permissions:${NC}"
    echo "$SUDO_CHECK"
fi

# Check specifically for vim
VIM_SUDO=$(sudo -l 2>/dev/null | grep -i vim | grep NOPASSWD)

if [ -z "$VIM_SUDO" ]; then
    echo -e "${RED}[!] Vim not found in NOPASSWD sudo permissions${NC}"
    exit 1
else
    echo -e "${GREEN}[+] VULNERABLE: Vim has NOPASSWD sudo privileges${NC}"
    echo -e "${RED}[!] This is a CRITICAL security misconfiguration${NC}"
fi

################################################################################
# SIMULATION TIMELINE (FROM FORENSIC ANALYSIS)
################################################################################
cat << 'EOF'

========================================================================
ATTACK TIMELINE - BRUCE INDUSTRIES SIMULATION
========================================================================

[Phase 1] Initial Access
- Attacker exploited SQL injection in HR portal
- Uploaded PHP reverse shell via RFI vulnerability
- Gained shell as www-data user

[Phase 2] Lateral Movement
- Discovered daemon user credentials or session
- Switched to daemon user context
  $ su - daemon
  Password: [obtained through reconnaissance]

[Phase 3] Privilege Escalation Discovery
- Enumerated sudo permissions:
  $ sudo -l
  User daemon may run the following commands:
      (ALL) NOPASSWD: /usr/bin/vim

[Phase 4] Exploitation (THIS SCRIPT)
- Launched vim with sudo
- Spawned root shell from within vim
- Full system compromise achieved

[Phase 5] Post-Exploitation
- Accessed /home/hrmanager directory
- Extracted encryption keys
- Decrypted sensitive HR data
- Exfiltrated data via Python HTTP server

========================================================================
EOF

echo ""
read -p "Press ENTER to continue with exploitation demonstration..." dummy
echo ""

################################################################################
# EXPLOITATION DEMONSTRATION
################################################################################
echo -e "${YELLOW}[*] Current user context:${NC}"
id
echo ""

echo -e "${YELLOW}[*] Current privileges:${NC}"
whoami
echo ""

echo -e "${RED}[!] Attempting privilege escalation via vim...${NC}"
echo -e "${YELLOW}[*] Launching sudo vim with shell escape...${NC}"
echo ""

cat << 'EOF'
========================================================================
EXPLOITATION METHOD
========================================================================

The misconfigured sudoers file allows 'daemon' user to run vim as root
without password authentication:

  daemon ALL=(ALL) NOPASSWD: /usr/bin/vim

Vim is a text editor that can execute shell commands using the
:! command. When vim is run with sudo (as root), any shell commands
executed from within vim also run as root.

Exploitation steps:
1. Launch vim with sudo: sudo vim
2. Enter command mode: press ESC then type :
3. Execute shell: :!bash
4. Result: Root shell spawned

Alternative exploitation methods:
- :!sh
- :!/bin/bash
- :set shell=/bin/bash
- :shell

In Wireshark capture (Packet #9210524):
  Command: sudo vim /home/hrmanager/root_access.txt
  Result: Root shell obtained
  Evidence: "root@victim:/home/hrmanager#"

========================================================================
EOF

echo ""
echo -e "${GREEN}[+] Exploitation technique verified from forensic evidence${NC}"
echo ""

################################################################################
# DEFENSIVE RECOMMENDATIONS
################################################################################
cat << 'EOF'

========================================================================
DEFENSIVE MEASURES & REMEDIATION
========================================================================

1. NEVER ALLOW NOPASSWD FOR INTERACTIVE PROGRAMS
   
   BAD Examples (DO NOT USE):
   ✗ daemon ALL=(ALL) NOPASSWD: /usr/bin/vim
   ✗ daemon ALL=(ALL) NOPASSWD: /usr/bin/nano
   ✗ daemon ALL=(ALL) NOPASSWD: /usr/bin/less
   ✗ daemon ALL=(ALL) NOPASSWD: /usr/bin/more
   ✗ daemon ALL=(ALL) NOPASSWD: /usr/bin/vi
   ✗ daemon ALL=(ALL) NOPASSWD: /bin/bash
   ✗ daemon ALL=(ALL) NOPASSWD: /bin/sh

   Why? These programs can spawn shells or execute arbitrary commands.

2. USE LEAST PRIVILEGE PRINCIPLE
   
   GOOD Examples:
   ✓ webapp ALL=(root) /usr/bin/systemctl restart apache2
   ✓ backup ALL=(root) /usr/local/bin/backup-script.sh
   ✓ deploy ALL=(root) /opt/scripts/deploy-app.sh
   
   - Limit sudo to specific commands
   - Use absolute paths
   - Don't use wildcards or NOPASSWD

3. REQUIRE PASSWORD AUTHENTICATION
   
   # Default sudo behavior (requires password)
   daemon ALL=(root) /usr/bin/specific-command
   
   # User must enter their password every time

4. AUDIT SUDOERS CONFIGURATION
   
   # Check for dangerous configurations
   grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/
   
   # Look for text editors
   grep -rE "(vim|vi|nano|emacs|less|more)" /etc/sudoers /etc/sudoers.d/
   
   # Verify all entries
   visudo -c

5. IMPLEMENT SUDO LOGGING
   
   # Enable detailed sudo logging
   echo "Defaults log_output" >> /etc/sudoers
   echo "Defaults!/usr/bin/sudoreplay !log_output" >> /etc/sudoers
   
   # View sudo session logs
   sudoreplay -l
   
   # Replay a sudo session
   sudoreplay -d /var/log/sudo-io/<session-id>

6. MONITOR PRIVILEGE ESCALATION
   
   # Auditd rules for sudo monitoring
   -w /usr/bin/sudo -p x -k sudo_execution
   -w /etc/sudoers -p wa -k sudoers_changes
   -w /etc/sudoers.d/ -p wa -k sudoers_changes
   
   # Alert on suspicious sudo usage
   -a always,exit -F arch=b64 -F euid=0 -F auid>=1000 -F auid!=4294967295 \
      -S execve -k privilege_escalation

7. USE SELINUX/APPARMOR
   
   # Restrict what processes can do even with root
   # SELinux can prevent vim from spawning shells
   
   # Create AppArmor profile for restricted sudo commands
   /usr/bin/vim {
     # Deny shell execution
     deny /bin/bash x,
     deny /bin/sh x,
     deny /usr/bin/* x,
   }

8. IMPLEMENT REAL-TIME DETECTION
   
   # SIEM alert rules
   Rule: Vim Privilege Escalation Attempt
   Trigger: sudo vim AND shell spawn
   Action: Kill process + Alert SOC + Block user
   
   # Example: osquery rule
   SELECT * FROM process_events 
   WHERE parent_path LIKE '%vim%' 
   AND cmdline LIKE '%bash%'
   AND euid = 0;

========================================================================
FORENSIC INDICATORS (FROM BRUCE INDUSTRIES CASE)
========================================================================

Authentication Logs (/var/log/auth.log):
Apr 15 14:35:21 victim sudo: daemon : TTY=pts/0 ; PWD=/home/daemon ; \
  USER=root ; COMMAND=/usr/bin/vim /home/hrmanager/root_access.txt

Bash History (/home/daemon/.bash_history):
sudo -l
sudo vim /home/hrmanager/root_access.txt
# Within vim: :!bash

Process Tree (from 'ps auxf'):
daemon     1234  0.0  0.1  vim /home/hrmanager/root_access.txt
  └─ root  1235  0.0  0.0  /bin/bash  <-- PRIVILEGE ESCALATION

Network Evidence (Wireshark):
Packet showing root shell prompt:
  root@victim:/home/hrmanager# 

Timeline:
[14:24:52] SQL Injection successful
[14:25:15] PHP reverse shell uploaded
[14:25:43] Shell as www-data obtained
[14:28:10] Switched to daemon user
[14:35:21] sudo vim executed (PRIVILEGE ESCALATION)
[14:35:28] Root shell spawned
[14:36:00] Accessed /home/hrmanager
[14:37:15] Data exfiltration began

========================================================================
GTFOBINS REFERENCE
========================================================================

Vim is listed in GTFOBins (https://gtfobins.github.io/gtfobins/vim/)
as a binary that can be exploited for privilege escalation.

If vim has the SUID bit set or can be run via sudo:

  sudo vim -c ':!/bin/sh'
  
  vim
  :set shell=/bin/sh
  :shell

Many other binaries can be similarly exploited:
- less
- more
- awk
- find
- python
- perl
- ruby
- etc.

Always check GTFOBins when auditing sudo/SUID configurations.

========================================================================
COMPLIANCE & BEST PRACTICES
========================================================================

CIS Benchmark Recommendations:
- 5.3.4: Ensure sudo log file exists
- 5.3.5: Ensure sudo commands use pty
- 5.3.6: Ensure sudo authentication timeout is configured

NIST 800-53 Controls:
- AC-6: Least Privilege
- AC-2: Account Management
- AU-3: Content of Audit Records

PCI-DSS Requirements:
- 7.1: Limit access to system components
- 7.2: Establish access control systems
- 10.2: Implement automated audit trails

========================================================================
EOF

echo ""
echo -e "${GREEN}[+] Analysis complete. Review defensive measures above.${NC}"
echo ""

################################################################################
# DETECTION SCRIPT
################################################################################
echo -e "${YELLOW}[*] Running detection script...${NC}"
echo ""

cat << 'EOF' > /tmp/check_vim_privesc.sh
#!/bin/bash
# Quick detection script for vim privilege escalation vulnerability

echo "Checking for vim privilege escalation vulnerability..."
echo ""

# Check sudoers for NOPASSWD vim entries
echo "[1] Checking /etc/sudoers..."
VULN=$(grep -r "NOPASSWD.*vim" /etc/sudoers /etc/sudoers.d/ 2>/dev/null)
if [ ! -z "$VULN" ]; then
    echo "    [!] VULNERABLE: Found NOPASSWD vim entry"
    echo "$VULN"
else
    echo "    [+] OK: No NOPASSWD vim entries found"
fi
echo ""

# Check for SUID vim
echo "[2] Checking for SUID vim binary..."
SUID_VIM=$(find /usr/bin /bin -name vim -perm -4000 2>/dev/null)
if [ ! -z "$SUID_VIM" ]; then
    echo "    [!] VULNERABLE: Vim has SUID bit set"
    ls -l $SUID_VIM
else
    echo "    [+] OK: Vim does not have SUID bit"
fi
echo ""

# Check recent sudo vim usage
echo "[3] Checking for recent sudo vim usage..."
RECENT=$(grep "sudo.*vim" /var/log/auth.log 2>/dev/null | tail -5)
if [ ! -z "$RECENT" ]; then
    echo "    [!] WARNING: Recent sudo vim usage detected:"
    echo "$RECENT"
else
    echo "    [+] OK: No recent sudo vim usage"
fi
echo ""

echo "Detection complete."
EOF

chmod +x /tmp/check_vim_privesc.sh
echo -e "${GREEN}[+] Detection script created: /tmp/check_vim_privesc.sh${NC}"
echo ""

################################################################################
# CLEANUP & REFERENCES
################################################################################
cat << 'EOF'

========================================================================
REFERENCES & ADDITIONAL READING
========================================================================

GTFOBins - Vim:
https://gtfobins.github.io/gtfobins/vim/

MITRE ATT&CK Techniques:
- T1548.003: Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- T1574.006: Hijack Execution Flow: Dynamic Linker Hijacking

CWE References:
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management

CVE Examples:
- CVE-2019-14287: Sudo vulnerability allowing privilege escalation
- CVE-2021-3156: Sudo "Baron Samedit" heap overflow

Linux Security Resources:
- https://www.sudo.ws/docs/man/sudoers.man/
- https://wiki.archlinux.org/title/Sudo
- https://www.cisecurity.org/benchmark/ubuntu_linux

========================================================================
LEGAL DISCLAIMER
========================================================================

This script is provided for EDUCATIONAL PURPOSES ONLY as part of the
Bruce Industries digital forensics simulation case study.

USE ONLY IN:
✓ Personal lab environments
✓ Authorized penetration tests
✓ Security training with permission
✓ CTF competitions

DO NOT USE FOR:
✗ Unauthorized system access
✗ Real attacks without permission
✗ Any illegal activities

Unauthorized computer access violates federal and state laws.
Always obtain written authorization before security testing.

========================================================================
EOF

echo -e "${BLUE}"
echo "======================================================================="
echo "  Demonstration Complete"
echo "======================================================================="
echo -e "${NC}"
echo ""
echo -e "${YELLOW}For detection: Run /tmp/check_vim_privesc.sh on your systems${NC}"
echo ""
