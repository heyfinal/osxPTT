
# osxPTT - Auto Installer for Pentest Tools on Mac/OSX

![GitHub release (latest by date)](https://img.shields.io/github/v/release/heyfinal/osxPTT?style=for-the-badge)
![GitHub](https://img.shields.io/github/license/heyfinal/osxPTT?style=for-the-badge)
![GitHub last commit](https://img.shields.io/github/last-commit/heyfinal/osxPTT?style=for-the-badge)
![Hits](https://hits.sh/github.com/heyfinal/osxPTT.svg?style=for-the-badge)

Welcome to osxPTT, the ultimate auto-installer for pentesting tools on Mac/OSX. This script installs a variety of tools to prepare your Mac for pentesting adventures. Let’s face it, doing it manually is for rookies.

## Features

- Automated installation of pentesting tools.
- Comprehensive list of tools for various pentesting needs.
- Easy-to-follow commands and usage instructions.
- Professional and humorous approach to making your pentesting setup a breeze.

## Tools List

Here’s a breakdown of the tools that will be installed:

| Tool                   | Function                                                                 | Install Method  | Commands                                                                                   | Source                                    |
|------------------------|--------------------------------------------------------------------------|-----------------|--------------------------------------------------------------------------------------------|-------------------------------------------|
| radare2                | Reverse engineering beast.                                               | brew            | `r2 <binary>`                                                                             |                                           |
| cutter                 | GUI for Radare2.                                                         | brew cask       | `cutter`                                                                                   |                                           |
| ghidra                 | NSA’s reverse tool.                                                      | brew cask       | `ghidraRun`                                                                               |                                           |
| ida-free               | Free disassembler.                                                       | brew cask       | `ida64`                                                                                   |                                           |
| nmap                   | Badass network scanner.                                                  | brew            | `nmap -sV -Pn <target>`                                                                   |                                           |
| proxychains            | Proxy router.                                                            | brew            | `proxychains4 nmap <target>`                                                              |                                           |
| sqlmap                 | Auto-SQL injection tool.                                                 | brew            | `sqlmap -u 'http://target.com?id=1'`                                                      |                                           |
| powershell             | Windows scripting tool.                                                  | brew cask       | `pwsh`                                                                                    |                                           |
| impacket-scripts       | Network protocol toolkit.                                                | git             |                                                                                           | [Impacket GitHub](https://github.com/SecureAuthCorp/impacket.git) |
| powersploit            | PowerShell pentest scripts.                                              | git             |                                                                                           | [PowerSploit GitHub](https://github.com/PowerShellMafia/PowerSploit.git) |
| metasploit             | Exploit development framework.                                           | script          |                                                                                           | [Metasploit Script](https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb) |
| burpsuite              | Web vulnerability scanner and proxy.                                     | brew            | `burpsuite`                                                                               |                                           |
| john-jumbo             | Password cracker.                                                        | macport         | `john <file>`                                                                             |                                           |
| hashcat                | GPU hash-cracking tool.                                                  | brew            | `hashcat -m 0 -a 0 <hash> <wordlist>`                                                     |                                           |
| hash-id                | Hash identifier.                                                         | pip3            | `hashid <hash>`                                                                           |                                           |
| wireshark              | Packet sniffer.                                                          | brew cask       | `wireshark &`                                                                             |                                           |
| armitage               | Metasploit GUI.                                                          | brew cask       | `armitage`                                                                                |                                           |
| maltego                | OSINT graphing tool.                                                     | brew cask       | `maltego`                                                                                 |                                           |
| gobuster               | Directory and DNS brute-forcer.                                          | brew            | `gobuster dir -u <url> -w <wordlist>`                                                     |                                           |
| wfuzz                  | Web application fuzzer.                                                  | pip3            | `wfuzz -w <wordlist> -u <url>`                                                            |                                           |
| setoolkit              | Social engineering toolkit.                                              | git             |                                                                                           | [SET GitHub](https://github.com/trustedsec/social-engineer-toolkit.git) |
| exploitdb              | Exploit database.                                                        | brew            | `searchsploit <term>`                                                                     |                                           |
| evil-winrm             | WinRM shell.                                                             | gem             | `evil-winrm -i <ip> -u <user> -p <pass>`                                                  |                                           |
| masscan                | Mass IP scanner.                                                         | brew            | `masscan -p80,443 <range>`                                                                |                                           |
| nikto                  | Web server scanner.                                                      | brew            | `nikto -h <target>`                                                                       |                                           |
| lynis                  | System audit tool.                                                       | brew            | `lynis audit system`                                                                      |                                           |
| beef-xss               | Browser exploit framework.                                               | git             |                                                                                           | [Beef GitHub](https://github.com/beefproject/beef.git) |
| binwalk                | Firmware analyzer.                                                       | brew            | `binwalk <firmware.bin>`                                                                  |                                           |
| bulk_extractor         | Data carver.                                                             | brew            | `bulk_extractor -o output <file>`                                                         |                                           |
| w3af                   | Web application scanner.                                                 | git             |                                                                                           | [w3af GitHub](https://github.com/andresriancho/w3af.git) |
| wpscan                 | WordPress vulnerability scanner.                                         | brew            | `wpscan --url <url>`                                                                      |                                           |
| ipv6toolkit            | IPv6 pentest tools.                                                      | brew            | `scan6 -i <interface>`                                                                    |                                           |
| bettercap              | MITM tool.                                                               | brew            | `bettercap -iface wlan0`                                                                  |                                           |
| cewl                   | Wordlist generator.                                                      | git             |                                                                                           | [CeWL GitHub](https://github.com/digininja/CeWL.git) |
| crunch                 | Wordlist maker.                                                          | brew            | `crunch 6 6`                                                                              |                                           |
| hydra                  | Password cracker.                                                        | brew            | `hydra -l admin -P <wordlist> ssh://<target>`                                             |                                           |
| ncrack                 | Network cracker.                                                         | brew            | `ncrack -p ssh <target>`                                                                  |                                           |
| seclists               | Wordlist collection.                                                     | git             |                                                                                           | [SecLists GitHub](https://github.com/danielmiessler/SecLists.git) |
| truecrack              | TrueCrypt cracker.                                                       | brew            | `truecrack -t <file> -w <wordlist>`                                                       |                                           |
| webshells              | Web shell collection.                                                    | custom          | Download from [webshell repo](https://github.com/tennc/webshell)                          |                                           |
| weevely                | PHP web shell.                                                           | git             |                                                                                           | [Weevely GitHub](https://github.com/epinna/weevely3.git) |
| wordlists              | Custom wordlist stash.                                                   | custom          | Grab from repos like SecLists or custom sources manually.                                 |                                           |
| dex2jar                | Android DEX converter.                                                   | brew            | `d2j-dex2jar <apk>`                                                                       |                                           |
| gdb                    | Debugger.                                                                | brew            | `gdb <binary>`                                                                            |                                           |
| jd-gui                 | Java decompiler.                                                         | brew cask       | `jd-gui`                                                                                  |                                           |
| dos2unix               | Line-ending converter.                                                   | brew            | `dos2unix <file>`                                                                         |                                           |
| exiftool               | Metadata extractor.                                                      | brew            | `exiftool <file>`                                                                         |                                           |
| steghide               | Steganography tool.                                                      | port            | `steghide embed -cf <cover> -ef <embed>`                                                  |                                           |
| pwntools               | Exploit development toolkit.                                             | brew            | `pwn template <binary>`                                                                   |                                           |
| snort                  | IDS/IPS.                                                                 | brew            | `snort -c snort.conf`                                                                     |                                           |
| volatility             | Memory forensics.                                                        | brew            | `vol -f <dump> imageinfo`                                                                 |                                           |
| dnspy                  | .NET debugger.                                                           | windows         | Install via VirtualBox on Windows from [dnSpy GitHub](https://github.com/dnSpy/dnSpy)     |                                           |
| ilspy                  | .NET decompiler.                                                         | windows         | Install via VirtualBox on Windows from [ILSpy GitHub](https://github.com/icsharpcode/ILSpy) |                                           |
| immunity               | Exploit development debugger.                                            | windows         | Install via VirtualBox on Windows from [Immunity Debugger](https://www.immunityinc.com/products/debugger/) |                                           |
| virtualbox             | VM tool.                                                                 | brew cask       | `virtualbox`                                                                              |                                           |
| virtualbox-extension-pack | VBox extras.                                                         | brew cask       | Installed with brew cask                                                                  |                                           |
| selenium-server-standalone | Web automation.                                                    | brew            | `java -jar selenium-server-standalone.jar`                                                |                                           |
| owasp-zap              | Web vulnerability scanner.                                               | brew cask       | `zap.sh`                                                                                  |                                           |
| sslscan                | SSL/TLS scanner.                                                         | brew            | `sslscan <host>`                                                                          |                                           |
| dirb                   | Web directory brute-forcer.                                              | script          | [DIRB Script](https://sourceforge.net/projects/dirb/files/)                               |                                           |
| dirbuster              | Web directory brute-forcer.                                              | script          | [DirBuster Script](https://sourceforge.net/projects/dirbuster/files/)                     |                                           |
| osxfuse                | NTFS support for macOS.                                                  | brew            | Install via brew or build from git.                                                       |                                           |
| ettercap               | MITM attack kit.                                                         | brew            | `ettercap -T -M arp:remote /<target>// /<gateway>//`                                       |                                           |
| gophish                | Phishing framework.                                                      | git             |                                                                                           | [GoPhish GitHub](https://github.com/gophish/gophish.git) |
| xsser                  | XSS exploiter.                                                           | git             |                                                                                           | [XSSer GitHub](https://github.com/epsylon/xsser.git) |
| websploit              | Web pentest toolkit.                                                     | git             |                                                                                           | [WebSploit GitHub](https://github.com/The404Hacking/websploit.git) |
| testssl                | SSL/TLS tester.                                                          | brew            | `testssl.sh <host>`                                                                       |                                           |
| smbmap                 | SMB enumerator.                                                          | git             |                                                                                           | [SMBMap GitHub](https://github.com/ShawnDEvans/smbmap.git) |
| cmsmap                 | CMS scanner.                                                             | git             |                                                                                           | [CMSMap GitHub](https://github.com/Dionach/CMSmap.git) |
| webscarab              | Web proxy.                                                               | git             |                                                                                           | [WebScarab GitHub](https://github.com/OWASP/webscarab.git) |
| theharvester           | OSINT grabber.                                                           | brew            | `theharvester -d <domain> -b google`                                                      |                                           |
| subbrute               | Subdomain brute-forcer.                                                  | git             |                                                                                           | [SubBrute GitHub](https://github.com/TheRook/subbrute.git) |
| dnsrecon               | DNS enumerator.                                                          | git             |                                                                                           | [DNSRecon GitHub](https://github.com/darkoperator/dnsrecon.git) |
| dnsmap                 | DNS mapper.                                                              | svn             | [DNSMap SVN](https://code.google.com/archive/p/dnsmap/source/default/source)              |                                           |
| osint-framework        | OSINT toolkit.                                                           | git             |                                                                                           | [OSINT Framework GitHub](https://github.com/lockfale/OSINT-Framework.git) |
| zenmap                 | Nmap GUI.                                                                | brew cask       | `zenmap`                                                                                  |                                           |
| inetutils              | Network utilities.                                                       | brew            | `ping <host>`, `traceroute <host>`                                                        |                                           |
| arp-scan               | ARP scanner.                                                             | brew            | `arp-scan -l`, `arp-scan <range>`                                                         |                                           |
| macchanger             | MAC spoofing tool.                                                       | brew            |                                                                                           |                                           |
| murus                  | macOS firewall.                                                          | brew cask       | `murus`                                                                                   |                                           |
| angry-ip-scanner       | IP scanner.                                                              | brew cask       | `angryipscanner`                                                                          |                                           |
| sslstrip               | SSL downgrade tool.                                                      | git             |                                                                                           | [SSLStrip GitHub](https://github.com/moxie0/sslstrip.git) |
| ophcrack               | Windows password cracker.                                                | script          | [Ophcrack Script](https://ophcrack.sourceforge.net/download.php)                          |                                           |
| cyberchef              | Data transformation tool.                                                | git             |                                                                                           | [CyberChef GitHub](https://github.com/gchq/CyberChef.git) |
| brutespray             | Service brute-forcer.                                                    | git             |                                                                                           | [BruteSpray GitHub](https://github.com/x90skysn3k/brutespray.git) |
| johnny                 | John GUI.                                                                | script          | [Johnny Script](https://openwall.info/wiki/john/johnny)                                   |                                           |
| rhash                  | Hash calculator.                                                         | brew            | `rhash -c <file>`                                                                         |                                           |
| truecrack              | TrueCrypt cracker.                                                       | brew            | `truecrack -t <file> -w <wordlist>`                                                       |                                           |
| pkcrack                | ZIP cracker.                                                             | brew            | `pkcrack -c <cipher> -p <plain> -C <zip>`                                                 |                                           |
| lcrack                 | Password cracker.                                                        | brew            | `lcrack -m <method> <file>`                                                               |                                           |
| pdfcrack               | PDF password cracker.                                                    | brew            | `pdfcrack -f <file>`                                                                      |                                           |
| ddrescue               | Data recovery tool.                                                      | brew            | `ddrescue -f <source> <dest> <log>`                                                       |                                           |
| foremost               | File carver.                                                             | brew            | `foremost -i <image>`                                                                     |                                           |
| testdisk               | Disk recovery tool.                                                      | brew            | `testdisk`                                                                                |                                           |
| exif-untrasher         | Photo recovery tool.                                                     | script          | [Exif Untrasher](https://www.bluem.net/en/projects/exif-untrasher/)                       |                                           |
| cuckoo                 | Malware sandbox.                                                         | pip3            | `cuckoo`                                                                                  |                                           |
| powerfuzzer            | Web fuzzer.                                                              | git             |                                                                                           | [PowerFuzzer GitHub](https://github.com/jeffbryner/powerfuzzer.git) |
| wappalyzer             | Web technology detector.                                                 | web extension   | Install via Chrome/Firefox store.                                                         |                                           |
| hackbar                | Web pentest toolbar.                                                     | web extension   | Install via Chrome/Firefox store.                                                         |                                           |
| netdiscover            | Network scanner.                                                         | git             |                                                                                           | [NetDiscover GitHub](https://github.com/netdiscover-scanner/netdiscover.git) |


## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/heyfinal/osxPTT.git
   cd osxPTT
   ```

2. Run the installer script:
   ```sh
   python3 install_pentest_tools.py
   ```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to contribute.

## License

This project is not licenced & no warrenty provided, use / abuse code as you see fit.

## Connect with Me

[![Instagram](https://img.shields.io/badge/Instagram-%23E4405F.svg?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/danielgillaspy?igsh=MWRjeXJnOXo5aXhkYg%3D%3D&utm_source=qr)
[![Email](https://img.shields.io/badge/Email-daniel@gillaspy.me-blue?style=for-the-badge&logo=gmail&logoColor=white)](mailto:daniel@gillaspy.me)

---

*Remember, kids, when in doubt, brew it out!*

