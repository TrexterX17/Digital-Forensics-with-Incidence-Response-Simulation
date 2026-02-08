# Setup & Installation Guide

This guide will help you set up the Bruce Industries Forensics Simulation repository for educational use.

## 📋 Prerequisites

### Operating System
- **Recommended**: Linux (Ubuntu 20.04+, Kali Linux, or similar)
- **Alternative**: macOS, Windows with WSL2

### Required Software

```bash
# Update package lists
sudo apt-get update

# Install Python 3.8+
sudo apt-get install python3 python3-pip -y

# Install forensic tools (optional but recommended)
sudo apt-get install binutils -y  # For 'strings' command

# Install git
sudo apt-get install git -y
```

### Python Libraries

```bash
# Install required Python packages
pip install pillow numpy --break-system-packages

# Or use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install pillow numpy
```

## 📥 Installation

### Clone the Repository

```bash
# Clone from GitHub
git clone https://github.com/YOUR-USERNAME/bruce-industries-forensics-simulation.git

# Navigate to project directory
cd bruce-industries-forensics-simulation

# Verify structure
ls -la
```

### Verify Installation

```bash
# Check Python version
python3 --version  # Should be 3.8 or higher

# Test steganography scripts
cd scripts/steganography
python3 --version

# Test diagram generation
cd ../../diagrams
python3 generate_diagrams.py

# Run forensic analysis demo
cd ../scripts/forensics
chmod +x timeline_analysis.sh
./timeline_analysis.sh
```

## 🚀 Quick Start

### 1. Review the Documentation

```bash
# Read the main README
cat README.md

# Review forensic report
# Open docs/DF_Project.pdf in your PDF viewer

# Study lessons learned
cat docs/LESSONS_LEARNED.md
```

### 2. Examine Evidence Files

```bash
# Navigate to evidence directory
cd evidence

# View disk imaging screenshots
ls disk-imaging/

# Check phishing emails
ls phishing/

# Review exploitation evidence
ls exploitation/
```

### 3. Run Example Scripts

#### Steganography Demonstration

```bash
cd scripts/steganography

# Create a test image (you'll need a PNG file)
# Download a sample image or use your own
wget https://via.placeholder.com/800x600.png -O test_image.png

# Embed data
python3 embed_data.py test_image.png stego_output.png

# Extract data
python3 extract_data.py stego_output.png extracted.txt

# View extracted data
cat extracted.txt
```

#### Forensic Analysis

```bash
cd scripts/forensics

# Run timeline analysis demonstration
./timeline_analysis.sh

# View generated report template
cat /tmp/forensic_report_template.md
```

### 4. Generate Diagrams

```bash
cd diagrams

# Generate visual diagrams
python3 generate_diagrams.py

# View created diagrams
ls -lh *.png

# Open in image viewer
# xdg-open attack_timeline.png  # Linux
# open attack_timeline.png       # macOS
```

## 📚 Learning Path

### For Beginners

1. **Start with the README**: Understand the scenario
2. **Read the Executive Summary**: Get the high-level overview
3. **Review Evidence Files**: See what forensic evidence looks like
4. **Study the Timeline**: Follow the attack progression
5. **Read Lessons Learned**: Understand the takeaways

### For Intermediate Users

1. **Analyze the Scripts**: Study the attack and forensic code
2. **Run the Examples**: Execute the scripts to see them in action
3. **Review the Forensic Report**: Deep dive into the methodology
4. **Examine Network Captures**: Understand packet analysis
5. **Practice Detection**: Write rules based on IOCs

### For Advanced Users

1. **Recreate the Scenario**: Set up VMs and simulate the attack
2. **Improve Detection**: Develop better monitoring rules
3. **Contribute**: Add new scenarios or improve existing ones
4. **Teach Others**: Use this as training material
5. **Research**: Explore variations and additional techniques

## 🛠️ Optional Tools

### Forensic Analysis Tools

```bash
# Install Autopsy (GUI)
sudo apt-get install autopsy

# Install The Sleuth Kit
sudo apt-get install sleuthkit

# Install Wireshark
sudo apt-get install wireshark

# Install additional forensic utilities
sudo apt-get install foremost scalpel binwalk
```

### Virtual Lab Setup

For hands-on practice:

```bash
# Install VirtualBox
sudo apt-get install virtualbox

# Or install VMware Workstation Player
# Download from: https://www.vmware.com/products/workstation-player.html

# Download vulnerable VMs from:
# - VulnHub: https://www.vulnhub.com/
# - HackTheBox: https://www.hackthebox.com/
```

## 🔧 Troubleshooting

### Python Module Issues

```bash
# If PIL/Pillow not found
pip install --upgrade pillow

# If numpy issues
pip install --upgrade numpy

# If permission denied
pip install --user pillow numpy
```

### Script Execution Issues

```bash
# If script not executable
chmod +x script_name.sh

# If Python not found
# Check Python location
which python3

# Update shebang if needed
sed -i 's|#!/usr/bin/env python3|#!/usr/bin/python3|' script.py
```

### Forensic Tool Issues

```bash
# If 'strings' command not found
sudo apt-get install binutils

# If Autopsy issues
# Follow official installation guide:
# https://sleuthkit.org/autopsy/
```

## 📖 Additional Resources

### Documentation
- [Main README](README.md)
- [Lessons Learned](docs/LESSONS_LEARNED.md)
- [Contributing Guide](CONTRIBUTING.md)
- [License](LICENSE)

### External Resources
- **SANS Digital Forensics**: https://www.sans.org/digital-forensics/
- **Autopsy Docs**: https://sleuthkit.org/autopsy/docs/
- **Wireshark Tutorial**: https://www.wireshark.org/docs/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

## 🆘 Getting Help

### Issues & Questions

1. **Check existing issues**: [GitHub Issues](../../issues)
2. **Search documentation**: Use Ctrl+F in README files
3. **Open a new issue**: Provide details about your problem
4. **Community forums**: Ask on relevant security forums

### Support Channels

- **GitHub Issues**: Technical problems and bugs
- **Discussions**: General questions and ideas
- **Pull Requests**: Contributions and improvements

## ✅ Verification Checklist

After setup, verify you can:

- [ ] View all documentation files
- [ ] Access evidence screenshots
- [ ] Run Python scripts successfully
- [ ] Generate diagrams
- [ ] Execute bash scripts
- [ ] View generated timelines

## 🎓 Next Steps

Once setup is complete:

1. **Read through the full forensic report** (`docs/DF_Project.pdf`)
2. **Study each phase** of the attack timeline
3. **Examine the evidence** files in detail
4. **Try to recreate** the analysis yourself
5. **Contribute** improvements back to the project

## 📧 Contact

For setup issues or questions:
- Open an issue in the repository
- Check the CONTRIBUTING.md file
- Review closed issues for similar problems

---

**Happy Learning!** 🔍🔐

Remember: This is for **educational purposes only**. Always obtain proper authorization before performing security testing on any system you don't own.
