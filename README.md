# PRACTICAL WORK:
# REVERSE ENGINEERING AND CRACKING OF A FIRMWARE

# Introduction

The primary objective of this report is to demonstrate ho i uncovered, analyzed and exploited a firmware image from a Zyxel device, focusing on identifying vulnerabilities, specifically CVE-2020-29583 . I'm also going to reflect on the challenges and missteps encountred along the way.

But before im giving a small overview of the vulnerability.

# CVE-2020-29583: Hardcoded Credential Vulnerability

CVE-2020-29583 is a critical vulnerability affecting various Zyxel devices, including firewalls, VPN gateways, and access points. This flaw involves a hardcoded administrative account with the username and the password. These credentials are embedded directly within the firmware and provide full administrative privileges. This backdoor account can be exploited by attackers to gain unauthorized access to the device, potentially compromising the entire network.

According to Zyxel’s advisory, the following devices were impacted:

- USG Series: Unified Security Gateways

- ATP Series: Advanced Threat Protection Firewalls

- VPN Series: VPN Gateways

- NXC Series: Wireless LAN Controllers

for more informations check the following link :

https://nvd.nist.gov/vuln/detail/cve-2020-29583

# Preparation Phase

## Tools and Environment Setup

The preparation phase involved setting up the necessary tools and creating a controlled environment for firmware analysis. The following tools were installed and configured:

- Binwalk: A firmware analysis tool used for extracting and inspecting embedded filesystems.

  ```bash
  sudo apt-get install binwalk
  ```

- PkCrack: Breaking PkZip-encryption

  ```bash
  git clone https://github.com/keyunluo/pkcrack
  mkdir pkcrack/build
  cd pkcrack/build
  cmake ..
  make
  ```

- Hashcat: A powerful password recovery tool utilized for cracking hashed credentials.

  ```bash
  sudo apt install hashcat
  ```

- SquashFS Tools: Essential for extracting and mounting SquashFS filesystems contained within the firmware.



The work was done on a Kali Linux machine.

# First step: Analysis

## step a

After downloading the archive we proceed to unzipping it using the following command : 

``` bash
unzip 455ABUJ0C0-WK30-r95234-mod.zip -d firm
```

![image](https://github.com/user-attachments/assets/bd80dcfb-7977-4a30-b0e5-fbbd2e32f12f)

for the first time it was a bit confusing for me but after a quick look on the files i started getting the picture.

- 455ABUJ0C0.bin: the firmware binary.

- 455ABUJ0C0.conf: A configuration file.

- 455ABUJ0C0.db: a database file.

- 455ABUJ0C0.ri: Unknown purpose.

- and some **PDF**s that contain Documetation which is going to be helpful after.

