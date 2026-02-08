#!/usr/bin/env python3
"""
Steganography Data Extraction Script
Bruce Industries Forensics Simulation

⚠️  FOR EDUCATIONAL PURPOSES ONLY

This script extracts hidden data from steganographic images using LSB technique.
Matches the forensic analysis performed during the Bruce Industries simulation.

Author: Security Research Team
Date: 2025
"""

import sys
import os
from PIL import Image
import numpy as np

class SteganographyExtractor:
    """
    LSB (Least Significant Bit) Steganography Extraction
    
    Extracts hidden data embedded in the least significant bits of pixel values.
    """
    
    def __init__(self, image_path):
        """Initialize with stego image path"""
        self.image_path = image_path
        self.image = None
        
    def load_image(self):
        """Load the stego image"""
        try:
            self.image = Image.open(self.image_path)
            print(f"[+] Loaded stego image: {self.image_path}")
            print(f"    Size: {self.image.size}")
            print(f"    Mode: {self.image.mode}")
            return True
        except Exception as e:
            print(f"[!] Error loading image: {e}")
            return False
    
    def binary_to_text(self, binary_str):
        """Convert binary string to text"""
        # Split into 8-bit chunks
        chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
        # Convert each chunk to character
        text = ''.join(chr(int(char, 2)) for char in chars if len(char) == 8)
        return text
    
    def extract_data(self):
        """
        Extract hidden data from image using LSB steganography
        
        Returns:
            Extracted text data or None if extraction fails
        """
        if self.image is None:
            print("[!] No image loaded")
            return None
        
        print("[*] Extracting LSB data from image...")
        
        # Convert image to numpy array
        img_array = np.array(self.image)
        
        # Flatten array to 1D
        flat_array = img_array.flatten()
        
        # Extract LSB from each pixel
        binary_data = ''.join(str(pixel & 1) for pixel in flat_array)
        
        print(f"[*] Extracted {len(binary_data)} bits")
        
        # Convert binary to text
        text_data = self.binary_to_text(binary_data)
        
        # Look for end delimiter
        if "<<<END>>>" in text_data:
            text_data = text_data.split("<<<END>>>")[0]
            print("[+] Found end delimiter")
        else:
            print("[!] Warning: End delimiter not found")
            # Try to extract until we hit garbage
            # Usually non-printable characters indicate end of hidden data
            printable_data = ""
            for char in text_data:
                if char.isprintable() or char in ['\n', '\r', '\t']:
                    printable_data += char
                elif len(printable_data) > 100:  # Significant data extracted
                    break
            text_data = printable_data
        
        return text_data

def analyze_with_strings_method(image_path):
    """
    Alternative extraction using strings method
    This was the actual method used in the forensic investigation
    """
    print()
    print("[*] Alternative extraction method: strings utility")
    print("    (This is how it was discovered in the actual incident)")
    print()
    
    try:
        import subprocess
        result = subprocess.run(['strings', image_path], 
                              capture_output=True, 
                              text=True)
        
        if result.returncode == 0:
            output = result.stdout
            # Look for CSV-like data
            lines = output.split('\n')
            csv_lines = [line for line in lines if ',' in line and 
                        any(keyword in line.upper() for keyword in ['EID', 'SSN', 'EMPLOYEE'])]
            
            if csv_lines:
                print("[+] Possible hidden data found using strings:")
                print("-" * 70)
                for line in csv_lines[:10]:  # Show first 10 lines
                    print(line)
                if len(csv_lines) > 10:
                    print(f"... and {len(csv_lines) - 10} more lines")
                print("-" * 70)
                return True
            else:
                print("[!] No obvious CSV data found with strings method")
        else:
            print("[!] strings command failed")
            print("    Install with: sudo apt-get install binutils")
    except FileNotFoundError:
        print("[!] 'strings' command not found")
        print("    Install with: sudo apt-get install binutils")
    except Exception as e:
        print(f"[!] Error running strings: {e}")
    
    return False

def save_extracted_data(data, output_file):
    """Save extracted data to file"""
    try:
        with open(output_file, 'w') as f:
            f.write(data)
        print(f"[+] Extracted data saved to: {output_file}")
        return True
    except Exception as e:
        print(f"[!] Error saving data: {e}")
        return False

def main():
    """Main execution function"""
    
    print("=" * 70)
    print("  Steganography Data Extraction Tool")
    print("  Bruce Industries Forensics Simulation")
    print("=" * 70)
    print()
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 extract_data.py <stego_image> [output_file]")
        print()
        print("Example:")
        print("  python3 extract_data.py Peter.png extracted_data.csv")
        print()
        sys.exit(1)
    
    stego_image = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "extracted_data.txt"
    
    # Validate stego image exists
    if not os.path.exists(stego_image):
        print(f"[!] Error: Stego image not found: {stego_image}")
        sys.exit(1)
    
    # Create extractor instance
    extractor = SteganographyExtractor(stego_image)
    
    # Load image
    if not extractor.load_image():
        sys.exit(1)
    
    print()
    print("[*] Beginning data extraction...")
    print()
    
    # Extract data
    extracted_data = extractor.extract_data()
    
    if extracted_data:
        print()
        print("[+] Extraction successful!")
        print()
        print("=" * 70)
        print("  EXTRACTED DATA PREVIEW")
        print("=" * 70)
        print()
        
        # Show first 500 characters
        preview = extracted_data[:500]
        print(preview)
        if len(extracted_data) > 500:
            print(f"\n... ({len(extracted_data) - 500} more characters)")
        print()
        
        # Save to file
        if save_extracted_data(extracted_data, output_file):
            print()
            print(f"[+] Full data saved to: {output_file}")
    else:
        print()
        print("[!] No data extracted using LSB method")
    
    # Try strings method (forensic discovery method)
    analyze_with_strings_method(stego_image)
    
    print()
    print("=" * 70)
    print("  FORENSIC ANALYSIS NOTES")
    print("=" * 70)
    print()
    print("Bruce Industries Incident Timeline:")
    print("  1. Employee 'faraz' accessed HR encrypted archives")
    print("  2. Extracted encryption keys from hrmanager directory")
    print("  3. Decrypted sensitive employee data (SPII)")
    print("  4. Embedded data in Peter.png using steganography")
    print("  5. Deleted original CSV to cover tracks")
    print()
    print("Discovery Method:")
    print("  • Forensic analyst examined /home/faraz/ directory")
    print("  • Ran 'strings Peter.png' utility")
    print("  • Discovered CSV-formatted employee data with SSNs")
    print("  • Confirmed data exfiltration attempt")
    print()
    print("Command used in investigation:")
    print("  $ strings Peter.png | grep -i 'EID'")
    print()
    print("Evidence Location:")
    print("  Disk Image: /mnt/forensics/victim_disk.E01")
    print("  File Path: /home/faraz/Peter.png")
    print("  SHA-256: [See forensic report]")
    print()

if __name__ == "__main__":
    main()

"""
================================================================================
DETAILED FORENSIC ANALYSIS - BRUCE INDUSTRIES CASE
================================================================================

File: Peter.png
Location: /home/faraz/Peter.png
Size: 487,362 bytes
Created: 2025-04-15 13:52:25
Modified: 2025-04-15 13:52:25
Accessed: 2025-04-15 13:52:30

Discovery Process:
1. Autopsy disk analysis revealed unusual image file in user directory
2. Initial inspection using 'strings' utility
3. CSV-formatted data discovered containing SPII:
   - Employee IDs
   - Full names
   - Social Security Numbers

Command Output (from investigation):
$ strings Peter.png

HDR
DATx
zzkF
.632
+Rm
ic(8o
Z_;
:56q
("  )
ku-
$b7
C^a7
J7Ee
lwz
"!s
+D
^<{
++rZ
Roi
%]6
xoo
'3:
t}:(
hrIQi
\m+
Employee ID,Full Name,SSN          <-- SUSPICIOUS DATA FOUND
EID1023,James McKenzie,694-22-7813
EID1024,Alexis Knight,106-99-8878
[... more employee records ...]

Significance:
The presence of structured CSV data within an image file immediately raised
red flags. This data matched format of files in /home/hrmanager/ directory,
confirming unauthorized access and data concealment.

Auth Log Correlation:
$ grep "faraz" /var/log/auth.log | grep sudo

Apr 15 13:45:10 victim sudo: faraz : TTY=pts/1 ; PWD=/home/faraz ; 
  USER=root ; COMMAND=/usr/bin/cp /home/hrmanager/keys.txt /home/faraz/

Apr 15 13:47:28 victim sudo: faraz : TTY=pts/1 ; PWD=/home/faraz ;
  USER=root ; COMMAND=/usr/bin/openssl aes-256-cbc -d -in ...

Bash History Evidence:
$ cat /home/faraz/.bash_history

cd /home/hrmanager
ls -la
sudo cp encrypted_data.tar.gz /home/faraz/
cd
sudo cp /home/hrmanager/keys.txt .
openssl aes-256-cbc -d -in encrypted_data.tar.gz -out employee_data.csv -k ...
python3 steganography.py
ls -la Peter.png
rm employee_data.csv
history -c

Python Script Found:
$ cat /home/faraz/steganography.py

# Simple LSB steganography implementation
# Used to hide employee data in image

from PIL import Image

def hide_data(image_path, data, output_path):
    img = Image.open(image_path)
    # [LSB embedding code similar to our embed_data.py]
    # ...
    img.save(output_path)

# Usage
hide_data('blank_image.png', open('employee_data.csv').read(), 'Peter.png')

================================================================================
STEGANALYSIS TECHNIQUES
================================================================================

1. Visual Analysis
   - Look for unusual artifacts or distortions
   - Compare with known clean images
   - Check for inconsistencies in compression

2. Statistical Analysis
   - Chi-Square Test: Detect non-random LSB patterns
   - RS Analysis: Identify LSB modifications
   - Sample Pairs Analysis: Detect embedded messages

3. Histogram Analysis
   - Check for unusual frequency distributions
   - Look for pairs of values (LSB embedding artifact)

4. File Size Analysis
   - Compare expected vs. actual file size
   - Stego images may be larger than expected

5. Metadata Examination
   - Check EXIF data for inconsistencies
   - Look for editing software traces
   - Verify timestamps

Tools for Steganalysis:
- StegExpose: Automated LSB detection
- StegDetect: Detect various stego algorithms
- StegSecret: Extract hidden data
- OutGuess: Statistical steganalysis
- Binwalk: Firmware analysis and extraction
- Zsteg: PNG/BMP analysis tool

Example Commands:
$ stegdetect Peter.png
Peter.png : negative

$ zsteg Peter.png
imagedata           .. file: data
b1,r,lsb,xy         .. text: "Employee ID,Full Name,SSN\nEID1023,..."

$ binwalk Peter.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 800 x 600, 8-bit/color RGB

================================================================================
PREVENTION & DETECTION
================================================================================

Data Loss Prevention (DLP):
1. Monitor file operations on sensitive data
2. Scan outbound files for embedded data
3. Alert on unusual file access patterns
4. Block unauthorized file transfers

File Integrity Monitoring (FIM):
1. Hash all files in sensitive directories
2. Alert on any modifications
3. Track file access timestamps
4. Monitor sudo usage for file operations

User Behavior Analytics (UBA):
1. Establish baseline behavior per user
2. Alert on anomalous activity:
   - Unusual file access
   - After-hours activity
   - Bulk data operations
   - File hiding attempts

Network Monitoring:
1. Inspect all outbound traffic
2. Scan for steganographic content
3. Monitor unusual data transfers
4. Implement egress filtering

Security Awareness:
1. Train employees on data handling policies
2. Emphasize reporting suspicious activity
3. Create clear incident reporting procedures
4. Build trust-based security culture

================================================================================
LEGAL & COMPLIANCE
================================================================================

Data Protection Regulations:
- GDPR: Requires protection of personal data
- HIPAA: Healthcare information protection
- PCI-DSS: Payment card data security
- SOX: Financial data integrity

Incident Response Requirements:
1. Preserve evidence chain of custody
2. Document all forensic procedures
3. Notify affected individuals (breach laws)
4. Report to regulatory bodies if required
5. Conduct thorough post-incident review

Legal Considerations:
- Steganography itself is not illegal
- Unauthorized data exfiltration IS illegal
- Using stego to hide illegal activity is illegal
- Corporate data theft has civil and criminal penalties

================================================================================
EDUCATIONAL REFERENCES
================================================================================

Academic Papers:
- "Information Hiding Using LSB Steganography" (IEEE)
- "A Novel Approach for Detecting LSB Steganography" (ACM)
- "Steganalysis of LSB Matching Using Chi-Square Test" (Springer)

Books:
- "Digital Forensics Basics" - Sammons, J.
- "The Art of Memory Forensics" - Ligh, Case, Levy
- "Practical Forensic Imaging" - Leighton, B.

Online Resources:
- SANS Digital Forensics blog
- Autopsy documentation
- NIST Digital Forensics guides
- Forensics Focus community

Standards & Frameworks:
- NIST SP 800-86: Integration of Forensics Techniques
- ISO/IEC 27037: Digital Evidence Identification
- RFC 3227: Evidence Collection and Archiving

================================================================================
"""
