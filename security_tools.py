#!/usr/bin/env python3
"""
Security Tools Installer
Author: PrimordialOrigin

A comprehensive installer for various security testing and analysis tools.
LEGAL NOTICE: Use only on systems you own or have explicit permission to test.
"""

import os
import sys
import subprocess

# Tool Categories
NETWORK_TOOLS = [
    "nmap",
    "wireshark",
    "tcpdump",
    "net-tools",
    "dnsutils",
    "netcat-traditional",
    "iftop",
    "nethogs",
    "arpwatch",
    "masscan",
    "hping3",
    "traceroute",
    "mtr",
    "etherape",
]

FORENSICS_TOOLS = [
    "lynis",
    "chkrootkit",
    "testdisk",
    "sleuthkit",
    "binwalk",
    "rkhunter",
    "foremost",
    "scalpel",
    "gddrescue",
    "aide",
]

WEB_TOOLS = [
    "sqlmap",
    "gobuster",
    "nikto",
    "curl",
    "w3m",
    "wfuzz",
    "dirb",
    "wpscan",
    "commix",
    "whatweb",
]

PASSWORD_TOOLS = [
    "john",
    "hashcat",
    "hydra",
    "medusa",
    "crunch",
    "cewl",
    "ophcrack",
]

WIRELESS_TOOLS = [
    "aircrack-ng",
    "reaver",
    "kismet",
    "cowpatty",
    "bluez",
]

VULN_TOOLS = [
    "metasploit-framework",
    "exploitdb",
    "wapiti",
]

REVERSE_ENG_TOOLS = [
    "radare2",
    "gdb",
    "binutils",
    "strace",
    "ltrace",
    "valgrind",
    "hexedit",
]

OSINT_TOOLS = [
    "exiftool",
]

CRYPTO_TOOLS = [
    "openssl",
    "gpg",
    "steghide",
]

PRIVACY_TOOLS = [
    "tor",
    "proxychains4",
    "privoxy",
    "macchanger",
    "bleachbit",
]

MONITORING_TOOLS = [
    "logwatch",
    "fail2ban",
    "snort",
    "suricata",
    "syslog-ng",
]

MOBILE_TOOLS = [
    "apktool",
    "adb",
]

POST_EXPLOIT_TOOLS = [
    "weevely",
    "netcat-traditional",
    "socat",
]

REPORTING_TOOLS = [
    "cherrytree",
    "zim",
    "gnote",
]

# Tools that require special installation (not in apt)
MANUAL_INSTALL_NOTES = {
    # Forensics
    'autopsy': 'Download from sleuthkit.org/autopsy or use: sudo add-apt-repository ppa:gift/stable',
    'volatility': 'Install via: pip3 install volatility3 or git clone from github.com/volatilityfoundation',
    'osquery': 'Download .deb from osquery.io or add their repository',
    
    # Web Tools
    'burpsuite': 'Download Community Edition from portswigger.net/burp/communitydownload',
    'zaproxy': 'Download from zaproxy.org or use snap: snap install zaproxy --classic',
    'ffuf': 'Install from: github.com/ffuf/ffuf/releases or apt in Kali',
    'sublist3r': 'Install via: pip3 install sublist3r or git clone',
    
    # Wireless
    'bully': 'Install from: github.com/kimocoder/bully (compile from source)',
    
    # Vulnerability Tools
    'openvas': 'Install via: sudo apt install gvm (Greenbone Vulnerability Manager)',
    'skipfish': 'May need: sudo apt install skipfish (check if available)',
    
    # OSINT
    'theharvester': 'Install via: pip3 install theHarvester or git clone from github.com/laramies',
    'metagoofil': 'Install via: pip3 install metagoofil or git clone',
    'spiderfoot': 'Install via: pip3 install spiderfoot or docker run spiderfoot',
    'maltego': 'Download Community Edition from maltego.com',
    'recon-ng': 'Install via: pip3 install recon-ng',
    'sherlock': 'Install via: git clone https://github.com/sherlock-project/sherlock',
    
    # Crypto
    'outguess': 'May be in repos as outguess, check availability',
    
    # Privacy
    'veracrypt': 'Download from veracrypt.fr or add PPA: sudo add-apt-repository ppa:unit193/encryption',
    'i2p': 'Download from geti2p.net or add their repository',
    'anonsurf': 'Available in Kali or from github.com/Und3rf10w/kali-anonsurf',
    
    # Monitoring
    'ossec-hids': 'Install from ossec.net or use: sudo apt install ossec-hids-agent',
    'graylog': 'Install via Docker or from graylog.org',
    'splunk': 'Download from splunk.com (free tier available)',
    'elk-stack': 'Install Elasticsearch, Logstash, Kibana separately or use Docker',
    
    # Mobile
    'dex2jar': 'Download from github.com/pxb1988/dex2jar/releases',
    'androguard': 'Install via: pip3 install androguard',
    'mobsf': 'Install via: docker pull opensecurity/mobile-security-framework-mobsf',
    'frida': 'Install via: pip3 install frida-tools',
    'objection': 'Install via: pip3 install objection',
    'drozer': 'Install from github.com/WithSecureLabs/drozer',
    
    # Reverse Engineering
    'ghidra': 'Download from ghidra-sre.org (requires Java)',
    'ida-free': 'Download from hex-rays.com/ida-free',
    'hopper': 'Download from hopperapp.com',
    
    # Post-Exploitation
    'empire': 'Install from github.com/BC-SECURITY/Empire',
    'powersploit': 'Download from github.com/PowerShellMafia/PowerSploit',
    'mimikatz': 'Windows tool - download from github.com/gentilkiwi/mimikatz',
    'chisel': 'Download from github.com/jpillora/chisel/releases',
    'ngrok': 'Download from ngrok.com',
    
    # Reporting
    'keepnote': 'No longer maintained. Use: pip install keepnote or use alternatives',
    'dradis': 'Install via: docker pull dradis/dradis or from dradisframework.com',
    'faraday': 'Install via: pip3 install faradaysec',
    'pipal': 'Install from github.com/digininja/pipal',
    'magictree': 'Download from magictree.com',
}

# Mapping of choices to categories
TOOL_CHOICES = {
    '1': ('Network Monitoring & Analysis', NETWORK_TOOLS),
    '2': ('System Auditing & Forensics', FORENSICS_TOOLS),
    '3': ('Web Security Testing', WEB_TOOLS),
    '4': ('Password Cracking & Authentication', PASSWORD_TOOLS),
    '5': ('Wireless Security', WIRELESS_TOOLS),
    '6': ('Vulnerability Scanning & Exploitation', VULN_TOOLS),
    '7': ('Reverse Engineering & Binary Analysis', REVERSE_ENG_TOOLS),
    '8': ('Social Engineering & OSINT', OSINT_TOOLS),
    '9': ('Cryptography & Steganography', CRYPTO_TOOLS),
    '10': ('Anonymity & Privacy Tools', PRIVACY_TOOLS),
    '11': ('Log Analysis & Monitoring', MONITORING_TOOLS),
    '12': ('Mobile Security Testing', MOBILE_TOOLS),
    '13': ('Post-Exploitation & Persistence', POST_EXPLOIT_TOOLS),
    '14': ('Reporting & Documentation', REPORTING_TOOLS),
}

# All tools combined
ALL_TOOLS_LISTS = [
    NETWORK_TOOLS, FORENSICS_TOOLS, WEB_TOOLS, PASSWORD_TOOLS, WIRELESS_TOOLS,
    VULN_TOOLS, REVERSE_ENG_TOOLS, OSINT_TOOLS, CRYPTO_TOOLS, PRIVACY_TOOLS,
    MONITORING_TOOLS, MOBILE_TOOLS, POST_EXPLOIT_TOOLS, REPORTING_TOOLS
]

def print_banner(text, color_code="94"):
    """Print a formatted banner with color."""
    width = 60
    print(f"\n\033[{color_code}m╔{'═' * (width - 2)}╗")
    print(f"║ {text.ljust(width - 4)} ║")
    print(f"╚{'═' * (width - 2)}╝\033[0m")

def check_sudo():
    """Check if sudo is available."""
    try:
        result = subprocess.run(['sudo', '-n', 'true'], 
                              capture_output=True, 
                              timeout=1)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def install_tools(tool_list):
    """Install the specified list of tools using apt."""
    # Remove duplicates and empty strings
    filtered_tool_list = list(set([tool for tool in tool_list if tool]))

    if not filtered_tool_list:
        print("\033[93mWarning:\033[0m No tools specified for installation.")
        return

    # Check for tools requiring manual installation
    manual_tools = [t for t in filtered_tool_list if t in MANUAL_INSTALL_NOTES]
    apt_tools = [t for t in filtered_tool_list if t not in MANUAL_INSTALL_NOTES]

    if manual_tools:
        print(f"\n\033[93m⚠️  Manual Installation Required:\033[0m")
        for tool in sorted(manual_tools):
            print(f"\n   • {tool}")
            print(f"     {MANUAL_INSTALL_NOTES[tool]}")
        print()

    if not apt_tools:
        print("\033[93mAll tools in this category require manual installation.\033[0m")
        return

    print(f"\n\033[96m-> Tools to install via apt:\033[0m")
    for i, tool in enumerate(sorted(apt_tools), 1):
        print(f"   {i}. {tool}")
    
    print(f"\n\033[93mTotal: {len(apt_tools)} packages\033[0m")
    
    filtered_tool_list = apt_tools
    
    # Confirm installation
    confirm = input("\nProceed with installation? [Y/n]: ").strip().lower()
    if confirm and confirm not in ['y', 'yes']:
        print("Installation cancelled.")
        return

    print("\n\033[93mYou will be prompted for your sudo password if needed.\033[0m")

    # Update package lists
    print("\n" + "="*60)
    print("Step 1: Updating package lists...")
    print("="*60)
    result = subprocess.run(['sudo', 'apt', 'update'], 
                          capture_output=False)
    
    if result.returncode != 0:
        print("\033[91mError:\033[0m Failed to update package lists.")
        return

    # Install tools
    print("\n" + "="*60)
    print("Step 2: Installing packages...")
    print("="*60)
    
    cmd = ['sudo', 'apt', 'install', '-y'] + filtered_tool_list
    result = subprocess.run(cmd, capture_output=False)

    # Summary
    print("\n" + "="*60)
    if result.returncode == 0:
        print_banner("✅ Installation Complete!", "92")
        print("\nAll selected tools have been installed successfully.")
        print("\033[93mNote:\033[0m Some tools may require additional configuration.")
    else:
        print_banner("⚠️  Installation Completed with Warnings", "93")
        print("\nSome packages may have failed to install.")
        print("Common reasons:")
        print("  • Package not available in your repositories")
        print("  • Package name differs on your distribution")
        print("  • Additional repositories needed (e.g., Kali repos)")
        print("\nCheck the output above for specific errors.")

def show_legal_notice():
    """Display legal and ethical usage notice."""
    print("\n\033[91m╔" + "═"*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "⚠️  LEGAL AND ETHICAL USAGE NOTICE ⚠️".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "═"*58 + "╝\033[0m")
    print("""
These tools are intended for:
  • Educational purposes and learning cybersecurity
  • Authorized security testing and penetration testing
  • Improving defensive security postures
  • Testing systems you OWN or have WRITTEN PERMISSION to test

UNAUTHORIZED USE IS ILLEGAL and may result in:
  • Criminal prosecution
  • Civil liability
  • Loss of employment and career damage

Legal practice platforms:
  • HackTheBox, TryHackMe, PentesterLab
  • Official bug bounty programs
  • Personal virtual labs
""")
    print("\033[91m" + "="*60 + "\033[0m\n")

def print_main_banner():
    """Print an awesome ASCII art banner."""
    banner = """
\033[96m
    ███████╗███████╗ ██████╗████████╗ ██████╗  ██████╗ ██╗     ███████╗
    ██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
    ███████╗█████╗  ██║        ██║   ██║   ██║██║   ██║██║     ███████╗
    ╚════██║██╔══╝  ██║        ██║   ██║   ██║██║   ██║██║     ╚════██║
    ███████║███████╗╚██████╗   ██║   ╚██████╔╝╚██████╔╝███████╗███████║
    ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
\033[0m
\033[93m              🔒 Security Tools Installer v2.0 🔒\033[0m
\033[90m              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
              Author: PrimordialOrigin | For Educational Use Only
              ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
"""
    print(banner)

def main_menu():
    """Display main menu and handle user choices."""
    while True:
        print_main_banner()
        
        print("\nSelect a category to install tools:\n")

        print("  \033[92m[1]\033[0m  Network Monitoring & Analysis")
        print("  \033[92m[2]\033[0m  System Auditing & Forensics")
        print("  \033[92m[3]\033[0m  Web Security Testing")
        print("  \033[92m[4]\033[0m  Password Cracking & Authentication")
        print("  \033[92m[5]\033[0m  Wireless Security")
        print("  \033[92m[6]\033[0m  Vulnerability Scanning & Exploitation")
        print("  \033[92m[7]\033[0m  Reverse Engineering & Binary Analysis")
        print("  \033[92m[8]\033[0m  Social Engineering & OSINT")
        print("  \033[92m[9]\033[0m  Cryptography & Steganography")
        print("  \033[92m[10]\033[0m Anonymity & Privacy Tools")
        print("  \033[92m[11]\033[0m Log Analysis & Monitoring")
        print("  \033[92m[12]\033[0m Mobile Security Testing")
        print("  \033[92m[13]\033[0m Post-Exploitation & Persistence")
        print("  \033[92m[14]\033[0m Reporting & Documentation")
        print()
        print("  \033[93m[15]\033[0m Install ALL Tools")
        print("  \033[96m[16]\033[0m View Legal Notice")
        print("  \033[91m[0]\033[0m  Exit")

        choice = input("\n\033[96mEnter your choice (0-16):\033[0m ").strip()

        if choice == '0':
            print("\n\033[92mThank you for using Security Tools Installer!\033[0m")
            print("Stay secure and ethical! 🔒\n")
            sys.exit(0)
        
        elif choice == '15':
            print_banner("Installing ALL Tools", "93")
            print("\n\033[93m⚠️  Warning:\033[0m This will install 100+ packages.")
            print("This may take a significant amount of time and disk space.\n")
            all_tools = [tool for tools in ALL_TOOLS_LISTS for tool in tools]
            install_tools(all_tools)
        
        elif choice == '16':
            show_legal_notice()
        
        elif choice in TOOL_CHOICES:
            name, tools = TOOL_CHOICES[choice]
            print_banner(f"Category: {name}", "94")
            install_tools(tools)
        
        else:
            print("\n\033[91m❌ Invalid choice.\033[0m Please enter 0-16.\n")

        input("\nPress Enter to continue...")

def main():
    """Main entry point."""
    try:
        # Show legal notice on first run
        show_legal_notice()
        
        # Warn if running as root
        if os.geteuid() == 0:
            print("\033[91m⚠️  Warning:\033[0m Running as root is not recommended.")
            print("This script will use 'sudo' when necessary.\n")
            confirm = input("Continue anyway? [y/N]: ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("Exiting for safety.")
                sys.exit(0)
        
        # Check if we can use sudo
        if not check_sudo() and os.geteuid() != 0:
            print("\n\033[93mNote:\033[0m You may be prompted for your password during installation.")
        
        # Start main menu
        main_menu()
    
    except KeyboardInterrupt:
        print("\n\n\033[93mInstallation interrupted by user.\033[0m")
        print("Exiting safely...\n")
        sys.exit(0)
    
    except EOFError:
        print("\n\033[91mError:\033[0m No interactive terminal detected.")
        print("This script requires an interactive terminal (TTY).\n")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n\033[91m❌ Unexpected error:\033[0m {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
