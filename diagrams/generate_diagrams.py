#!/usr/bin/env python3
"""
Attack Timeline Visualization Generator
Bruce Industries Forensics Simulation
"""

from PIL import Image, ImageDraw, ImageFont
import os

# Timeline data
timeline_events = [
    {
        "time": "13:30:00",
        "phase": "Initial Compromise",
        "event": "Phishing email received",
        "details": "From: alerts@coinbbase.com",
        "color": "#FF6B6B"
    },
    {
        "time": "13:30:15",
        "phase": "Initial Compromise",
        "event": "Wallet key exposed via TLS",
        "details": "2 BTC threatened",
        "color": "#FF6B6B"
    },
    {
        "time": "13:45:10",
        "phase": "Insider Actions",
        "event": "Accessed HR encrypted data",
        "details": "/home/hrmanager/encrypted_data.tar.gz",
        "color": "#FFA500"
    },
    {
        "time": "13:47:28",
        "phase": "Insider Actions",
        "event": "Extracted encryption keys",
        "details": "sudo cp /home/hrmanager/keys.txt",
        "color": "#FFA500"
    },
    {
        "time": "13:48:01",
        "phase": "Insider Actions",
        "event": "Decrypted employee data",
        "details": "openssl aes-256-cbc -d",
        "color": "#FFA500"
    },
    {
        "time": "13:52:18",
        "phase": "Data Concealment",
        "event": "Steganography script executed",
        "details": "python3 steganography.py",
        "color": "#FFD700"
    },
    {
        "time": "13:52:25",
        "phase": "Data Concealment",
        "event": "Data embedded in Peter.png",
        "details": "CSV data hidden in image",
        "color": "#FFD700"
    },
    {
        "time": "14:10:00",
        "phase": "Second Phishing",
        "event": "Follow-up instructions received",
        "details": "Introduce vulnerabilities",
        "color": "#FF6B6B"
    },
    {
        "time": "14:15:30",
        "phase": "Vulnerability Introduction",
        "event": "SQL injection added",
        "details": "/employee_pro/login.php modified",
        "color": "#9370DB"
    },
    {
        "time": "14:16:45",
        "phase": "Vulnerability Introduction",
        "event": "RFI vulnerability added",
        "details": "/employee_pro/upload.php modified",
        "color": "#9370DB"
    },
    {
        "time": "14:18:20",
        "phase": "Vulnerability Introduction",
        "event": "Sudoers misconfigured",
        "details": "daemon NOPASSWD: /usr/bin/vim",
        "color": "#9370DB"
    },
    {
        "time": "14:23:45",
        "phase": "External Exploitation",
        "event": "SQL injection exploited",
        "details": "' OR '1'='1 - Auth bypassed",
        "color": "#DC143C"
    },
    {
        "time": "14:24:52",
        "phase": "External Exploitation",
        "event": "PHP shell uploaded via RFI",
        "details": "php-reverse-shell.php",
        "color": "#DC143C"
    },
    {
        "time": "14:25:43",
        "phase": "External Exploitation",
        "event": "Shell access as www-data",
        "details": "10.200.0.129:4444 connected",
        "color": "#DC143C"
    },
    {
        "time": "14:28:10",
        "phase": "Lateral Movement",
        "event": "Switched to daemon user",
        "details": "su - daemon",
        "color": "#FF4500"
    },
    {
        "time": "14:35:21",
        "phase": "Privilege Escalation",
        "event": "sudo vim executed",
        "details": "Spawned root shell via :!bash",
        "color": "#8B0000"
    },
    {
        "time": "14:36:00",
        "phase": "Post-Exploitation",
        "event": "Accessed HR directory",
        "details": "cd /home/hrmanager",
        "color": "#800080"
    },
    {
        "time": "14:37:15",
        "phase": "Data Exfiltration",
        "event": "Python HTTP server started",
        "details": "python3 -m http.server 9999",
        "color": "#000080"
    },
    {
        "time": "14:38:30",
        "phase": "Data Exfiltration",
        "event": "Data downloaded",
        "details": "forensics_copy.tar.gz",
        "color": "#000080"
    }
]

def create_timeline_image():
    """Create a visual timeline of the attack"""
    
    # Image dimensions
    width = 1600
    height = 2400
    padding = 50
    event_height = 100
    
    # Create image
    img = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(img)
    
    # Try to use a font, fall back to default if not available
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 32)
        phase_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
        event_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
        time_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
    except:
        title_font = phase_font = event_font = time_font = ImageFont.load_default()
    
    # Title
    title = "Bruce Industries Attack Timeline"
    subtitle = "April 15, 2025 - Insider Threat Simulation"
    draw.text((width//2, 30), title, fill='black', font=title_font, anchor="mt")
    draw.text((width//2, 70), subtitle, fill='gray', font=event_font, anchor="mt")
    
    # Draw timeline
    timeline_x = 150
    timeline_start_y = 150
    timeline_end_y = height - 100
    
    # Vertical line
    draw.line([(timeline_x, timeline_start_y), (timeline_x, timeline_end_y)], 
             fill='black', width=3)
    
    # Plot events
    y_pos = timeline_start_y
    y_step = (timeline_end_y - timeline_start_y) / len(timeline_events)
    
    current_phase = ""
    
    for i, event in enumerate(timeline_events):
        y = timeline_start_y + (i * y_step)
        
        # Phase header (if changed)
        if event['phase'] != current_phase:
            current_phase = event['phase']
            draw.rectangle([(timeline_x + 30, y - 10), (width - padding, y + 25)],
                         fill='#F0F0F0', outline='black')
            draw.text((timeline_x + 40, y + 7), current_phase, 
                     fill='black', font=phase_font, anchor="lm")
            y += 40
        
        # Event node
        draw.ellipse([(timeline_x - 8, y - 8), (timeline_x + 8, y + 8)],
                    fill=event['color'], outline='black', width=2)
        
        # Time
        draw.text((timeline_x - 90, y), event['time'], 
                 fill='black', font=time_font, anchor="rm")
        
        # Event description
        draw.text((timeline_x + 25, y - 15), event['event'],
                 fill='black', font=event_font, anchor="lm")
        
        # Details
        draw.text((timeline_x + 25, y + 5), event['details'],
                 fill='gray', font=time_font, anchor="lm")
        
        # Connecting line
        draw.line([(timeline_x, y), (timeline_x + 20, y)],
                 fill=event['color'], width=2)
    
    # Legend
    legend_y = timeline_end_y + 30
    legend_items = [
        ("Initial Compromise", "#FF6B6B"),
        ("Insider Actions", "#FFA500"),
        ("Data Concealment", "#FFD700"),
        ("Vulnerability Introduction", "#9370DB"),
        ("External Exploitation", "#DC143C"),
        ("Privilege Escalation", "#8B0000"),
        ("Data Exfiltration", "#000080")
    ]
    
    draw.text((padding, legend_y), "Phase Legend:", fill='black', font=phase_font)
    legend_y += 30
    
    for label, color in legend_items:
        draw.rectangle([(padding, legend_y), (padding + 20, legend_y + 20)],
                      fill=color, outline='black')
        draw.text((padding + 30, legend_y + 10), label,
                 fill='black', font=event_font, anchor="lm")
        legend_y += 30
    
    return img

def create_network_topology():
    """Create a simple network topology diagram"""
    
    width = 1400
    height = 1000
    
    img = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(img)
    
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28)
        label_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
        ip_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
    except:
        title_font = label_font = ip_font = ImageFont.load_default()
    
    # Title
    draw.text((width//2, 30), "Network Topology - Bruce Industries Simulation", 
             fill='black', font=title_font, anchor="mt")
    
    # Internet cloud
    internet_x, internet_y = 700, 150
    draw.ellipse([(internet_x - 80, internet_y - 40), (internet_x + 80, internet_y + 40)],
                fill='#87CEEB', outline='black', width=2)
    draw.text((internet_x, internet_y), "Internet", fill='black', font=label_font, anchor="mm")
    
    # TLS Proxy
    proxy_x, proxy_y = 700, 300
    draw.rectangle([(proxy_x - 100, proxy_y - 40), (proxy_x + 100, proxy_y + 40)],
                  fill='#FFD700', outline='black', width=2)
    draw.text((proxy_x, proxy_y - 10), "TLS Interception Proxy", 
             fill='black', font=label_font, anchor="mm")
    draw.text((proxy_x, proxy_y + 15), "(SSL Proxy)", 
             fill='gray', font=ip_font, anchor="mm")
    
    # Firewall
    fw_x, fw_y = 700, 450
    draw.rectangle([(fw_x - 90, fw_y - 35), (fw_x + 90, fw_y + 35)],
                  fill='#FF6B6B', outline='black', width=2)
    draw.text((fw_x, fw_y), "Firewall / IDS", 
             fill='white', font=label_font, anchor="mm")
    
    # Internal Network line
    draw.line([(200, 600), (1200, 600)], fill='black', width=3)
    draw.text((700, 580), "Internal Network (10.200.0.0/24)", 
             fill='black', font=label_font, anchor="mm")
    
    # HR Server
    hr_x, hr_y = 400, 750
    draw.rectangle([(hr_x - 80, hr_y - 60), (hr_x + 80, hr_y + 60)],
                  fill='#90EE90', outline='black', width=2)
    draw.text((hr_x, hr_y - 20), "HR Web Server", 
             fill='black', font=label_font, anchor="mm")
    draw.text((hr_x, hr_y + 10), "10.200.0.91", 
             fill='black', font=ip_font, anchor="mm")
    draw.text((hr_x, hr_y + 30), "(VICTIM)", 
             fill='red', font=ip_font, anchor="mm")
    
    # Attacker system
    att_x, att_y = 1000, 750
    draw.rectangle([(att_x - 80, att_y - 60), (att_x + 80, att_y + 60)],
                  fill='#DC143C', outline='black', width=2)
    draw.text((att_x, att_y - 20), "Attacker System", 
             fill='white', font=label_font, anchor="mm")
    draw.text((att_x, att_y + 10), "10.200.0.129", 
             fill='white', font=ip_font, anchor="mm")
    
    # Workstation
    ws_x, ws_y = 250, 750
    draw.rectangle([(ws_x - 70, ws_y - 50), (ws_x + 70, ws_y + 50)],
                  fill='#ADD8E6', outline='black', width=2)
    draw.text((ws_x, ws_y - 10), "Employee", 
             fill='black', font=label_font, anchor="mm")
    draw.text((ws_x, ws_y + 15), "Workstation", 
             fill='black', font=label_font, anchor="mm")
    
    # Connection lines
    draw.line([(internet_x, internet_y + 40), (proxy_x, proxy_y - 40)],
             fill='blue', width=2)
    draw.line([(proxy_x, proxy_y + 40), (fw_x, fw_y - 35)],
             fill='blue', width=2)
    draw.line([(fw_x, fw_y + 35), (fw_x, 600)],
             fill='blue', width=2)
    
    # Attack path
    draw.line([(att_x, hr_y), (hr_x, hr_y)],
             fill='red', width=3)
    # Draw arrow manually
    arrow_x = hr_x + 60
    draw.polygon([(arrow_x, hr_y), (arrow_x + 20, hr_y - 10), (arrow_x + 20, hr_y + 10)],
                fill='red', outline='red')
    draw.text(((att_x + hr_x)//2, hr_y - 20), "Attack Path", 
             fill='red', font=label_font, anchor="mm")
    
    # Key
    key_x = 100
    key_y = 850
    draw.text((key_x, key_y), "Key:", fill='black', font=label_font)
    draw.line([(key_x, key_y + 25), (key_x + 50, key_y + 25)], 
             fill='blue', width=2)
    draw.text((key_x + 60, key_y + 25), "Normal Traffic", 
             fill='black', font=ip_font, anchor="lm")
    draw.line([(key_x, key_y + 50), (key_x + 50, key_y + 50)], 
             fill='red', width=3)
    draw.text((key_x + 60, key_y + 50), "Attack Traffic", 
             fill='black', font=ip_font, anchor="lm")
    
    return img

# Generate diagrams
print("Generating attack timeline diagram...")
timeline_img = create_timeline_image()
timeline_img.save("/home/claude/bruce-industries-forensics-simulation/diagrams/attack_timeline.png")
print("[+] Saved: attack_timeline.png")

print("Generating network topology diagram...")
network_img = create_network_topology()
network_img.save("/home/claude/bruce-industries-forensics-simulation/diagrams/network_topology.png")
print("[+] Saved: network_topology.png")

print("\nDiagrams created successfully!")
