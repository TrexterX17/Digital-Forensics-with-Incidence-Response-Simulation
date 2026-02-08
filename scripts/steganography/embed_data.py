#!/usr/bin/env python3
"""
Steganography Data Embedding Script
Bruce Industries Forensics Simulation

⚠️  FOR EDUCATIONAL PURPOSES ONLY

This script demonstrates the steganographic technique used to conceal
sensitive HR data within image files during the simulation.

Author: Security Research Team
Date: 2025
"""

import sys
import os
from PIL import Image
import numpy as np

class SteganographyEmbedder:
    """
    LSB (Least Significant Bit) Steganography Implementation
    
    This technique modifies the least significant bit of pixel values
    to encode hidden data. Since changing the LSB has minimal impact on
    color values, the changes are imperceptible to the human eye.
    """
    
    def __init__(self, image_path):
        """Initialize with image file path"""
        self.image_path = image_path
        self.image = None
        self.data = None
        
    def load_image(self):
        """Load the cover image"""
        try:
            self.image = Image.open(self.image_path)
            print(f"[+] Loaded image: {self.image_path}")
            print(f"    Size: {self.image.size}")
            print(f"    Mode: {self.image.mode}")
            return True
        except Exception as e:
            print(f"[!] Error loading image: {e}")
            return False
    
    def calculate_capacity(self):
        """Calculate maximum data capacity in bytes"""
        if self.image is None:
            return 0
        
        width, height = self.image.size
        # 3 channels (RGB) per pixel, 1 bit per channel
        # 8 bits = 1 byte
        capacity = (width * height * 3) // 8
        return capacity
    
    def text_to_binary(self, text):
        """Convert text to binary string"""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary
    
    def embed_data(self, secret_data, output_path):
        """
        Embed secret data into image using LSB steganography
        
        Args:
            secret_data: String data to hide
            output_path: Path to save stego image
        """
        if self.image is None:
            print("[!] No image loaded")
            return False
        
        # Add delimiter to mark end of data
        secret_data += "<<<END>>>"
        
        # Convert to binary
        binary_data = self.text_to_binary(secret_data)
        data_length = len(binary_data)
        
        # Check capacity
        capacity = self.calculate_capacity()
        if data_length > capacity:
            print(f"[!] Data too large. Need {data_length} bits, have {capacity} bits")
            return False
        
        print(f"[*] Embedding {len(secret_data)} characters ({data_length} bits)")
        print(f"[*] Image capacity: {capacity} bits ({capacity // 8} bytes)")
        
        # Convert image to numpy array for manipulation
        img_array = np.array(self.image)
        
        # Flatten array to 1D for easier bit manipulation
        flat_array = img_array.flatten()
        
        # Embed data bits into LSB of pixel values
        for i in range(data_length):
            # Set LSB of current pixel to current data bit
            flat_array[i] = (flat_array[i] & 0xFE) | int(binary_data[i])
        
        # Reshape back to original dimensions
        stego_array = flat_array.reshape(img_array.shape)
        
        # Convert back to image
        stego_image = Image.fromarray(stego_array.astype('uint8'))
        
        # Save stego image
        stego_image.save(output_path)
        print(f"[+] Stego image saved to: {output_path}")
        print(f"[+] Successfully embedded {len(secret_data)} characters")
        
        return True

def create_sample_employee_data():
    """
    Create sample employee data similar to what was found in simulation
    This matches the format found in the Peter.png file
    """
    sample_data = """Employee ID,Full Name,SSN
EID1023,James McKenzie,694-22-7813
EID1024,Alexis Knight,106-99-8878
EID1025,Brittany Johnson,159-77-7857
EID1026,Haley Harris,843-12-2686
EID1027,Samantha Savage,136-74-4273
EID1028,Melinda Torres,309-94-4515
EID1029,Emily Watkins,531-93-8018
EID1030,Michele Smith,204-91-3129
EID1031,Sean Petty,552-57-2208
EID1032,Amy Moyer,392-93-2615
EID1033,Jennifer Fleming,290-41-7920
EID1034,Laura Pierce,587-84-2329
EID1035,Katherine Ortiz,402-62-6303
EID1036,Cynthia Marshall,164-35-6683
EID1037,Charles Rivera,835-86-6188
EID1038,Theodore Smith,324-87-4168
EID1039,Vanessa Nguyen,754-51-2792
EID1040,Bobby Wood MD,152-51-8169
EID1041,Scott Garcia,116-86-7795
EID1042,Victor Reilly DVM,830-91-7003
EID1043,Timothy Barron,765-16-1321"""
    
    return sample_data

def main():
    """Main execution function"""
    
    print("=" * 70)
    print("  Steganography Data Embedding Tool")
    print("  Bruce Industries Forensics Simulation")
    print("=" * 70)
    print()
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 embed_data.py <cover_image> [output_image] [data_file]")
        print()
        print("Example:")
        print("  python3 embed_data.py original.png Peter.png employee_data.csv")
        print()
        print("If data_file not provided, will use sample employee data")
        sys.exit(1)
    
    cover_image = sys.argv[1]
    output_image = sys.argv[2] if len(sys.argv) > 2 else "stego_image.png"
    data_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    # Validate cover image exists
    if not os.path.exists(cover_image):
        print(f"[!] Error: Cover image not found: {cover_image}")
        sys.exit(1)
    
    # Load secret data
    if data_file and os.path.exists(data_file):
        with open(data_file, 'r') as f:
            secret_data = f.read()
        print(f"[+] Loaded data from: {data_file}")
    else:
        print("[*] Using sample employee data (SPII)")
        secret_data = create_sample_employee_data()
    
    # Create embedder instance
    embedder = SteganographyEmbedder(cover_image)
    
    # Load image
    if not embedder.load_image():
        sys.exit(1)
    
    # Embed data
    print()
    print("[*] Beginning data embedding...")
    print()
    
    if embedder.embed_data(secret_data, output_image):
        print()
        print("[+] Embedding successful!")
        print()
        print("=" * 70)
        print("  SIMULATION NOTES - BRUCE INDUSTRIES CASE")
        print("=" * 70)
        print()
        print("In the actual incident:")
        print("  • User 'faraz' embedded HR data in Peter.png")
        print("  • File location: /home/faraz/Peter.png")
        print("  • Data discovered using: strings Peter.png")
        print("  • Extraction script available: extract_data.py")
        print()
        print("Detection indicators:")
        print("  • Unusual file access patterns to HR directory")
        print("  • Image file in employee home directory")
        print("  • File entropy analysis may reveal hidden data")
        print()
        print("To extract hidden data:")
        print(f"  python3 extract_data.py {output_image}")
        print()
    else:
        print()
        print("[!] Embedding failed")
        sys.exit(1)

if __name__ == "__main__":
    main()

"""
================================================================================
FORENSIC ANALYSIS NOTES - BRUCE INDUSTRIES SIMULATION
================================================================================

Timeline of Events:
[2025-04-15 13:45:12] User 'faraz' accessed /home/hrmanager/encrypted_data.tar.gz
[2025-04-15 13:47:33] Decryption key extracted from hrmanager directory
[2025-04-15 13:48:01] Employee data decrypted to CSV format
[2025-04-15 13:52:18] Python steganography script executed
[2025-04-15 13:52:25] Data embedded into Peter.png
[2025-04-15 13:53:10] Original CSV deleted from /home/faraz/

Discovery Method:
During disk image analysis using Autopsy, investigators found Peter.png in
/home/faraz/ directory. Initial inspection with 'strings' utility revealed
CSV-formatted data containing SPII (Sensitive Personal Identifiable Information).

Command used:
$ strings Peter.png | grep -i "EID"

Output showed employee records with SSNs, confirming data exfiltration attempt.

Detection Techniques:
1. File Access Patterns - Monitor access to sensitive directories
2. Entropy Analysis - Stego images may have slightly higher entropy
3. Statistical Analysis - Chi-square test for LSB modifications
4. File Timeline - Correlate file creation with suspicious activity
5. Strings Utility - Simple but effective for text-based payloads

Steganalysis Tools:
- StegExpose: Detect LSB steganography
- StegDetect: Identify various stego methods
- Binwalk: Analyze file for embedded data
- Exiftool: Check metadata inconsistencies

Prevention Strategies:
1. Data Loss Prevention (DLP) monitoring
2. File integrity monitoring (FIM)
3. Restrict access to sensitive data
4. Monitor unusual file operations
5. Implement egress filtering

================================================================================
LEGAL & ETHICAL CONSIDERATIONS
================================================================================

This script is for EDUCATIONAL PURPOSES ONLY.

Appropriate Use Cases:
✓ Security research and training
✓ Digital watermarking (copyright protection)
✓ Covert communication in authorized scenarios
✓ Forensic investigation practice

Inappropriate Use Cases:
✗ Unauthorized data exfiltration
✗ Concealing malware
✗ Evading monitoring without authorization
✗ Any illegal activity

Steganography itself is not illegal, but using it to conceal illegal activity
or exfiltrate confidential data without authorization is a crime.

================================================================================
TECHNICAL REFERENCES
================================================================================

LSB Steganography:
- Least Significant Bit is the rightmost bit in binary representation
- Modifying LSB has minimal visual impact (±1 in 256 color values)
- For RGB image: 3 bits per pixel available for hiding data
- Capacity: (width × height × 3) / 8 bytes

Example:
Original pixel: (154, 201, 88) = (10011010, 11001001, 01011000)
Hidden bit:     1
Modified pixel: (154, 201, 89) = (10011010, 11001001, 01011001)
                                                               ^
Visual difference: Imperceptible to human eye

Academic Papers:
- "A Novel Steganographic Method Based on LSB" (IEEE)
- "Analysis of LSB Based Image Steganography Techniques" (IJCA)

Tools & Libraries:
- Steghide: Popular steganography tool
- OpenStego: Java-based stego tool
- PIL (Pillow): Python imaging library
- Stegano: Python steganography library

================================================================================
"""
