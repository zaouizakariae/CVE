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

## step "a"

After downloading the archive we proceed to unzipping it using the following command : 

``` bash
unzip 455ABUJ0C0-WK30-r95234-mod.zip -d firm
```

![image](https://github.com/user-attachments/assets/bd80dcfb-7977-4a30-b0e5-fbbd2e32f12f)

for the first time it was a bit confusing for me but after a quick look on the files i started getting the picture.

- 455ABUJ0C0.bin: the firmware binary.

- 455ABUJ0C0.conf: A configuration file.

- 455ABUJ0C0.db: A database file.

- 455ABUJ0C0.ri: Unknown purpose.

- and some **PDF**s that contain Documetation which is going to be helpful after.

## step "b"


This **455ABUJ0C0.bin** is the most critical file.
we tried to extract it but it was asking for a sort of password that we didnt have.

![image](https://github.com/user-attachments/assets/af985408-e45a-465a-bd61-3e830152913e)

so we needed to do a known-plaintext attack unstead of going with the classic brute-force (hint given in the document)

we used Binwalk to analyze and extract the content of the bin file :

```bash
binwalk -e 455ABUJ0C0.bin
```

we can notice the default configuration file path :

![image](https://github.com/user-attachments/assets/06e31c57-f1b1-404b-81a3-7ebd8b5fddf4)

and by reading the documentation we knew tha we got the plain-text version **455ABUJ0C0.conf** :

![image](https://github.com/user-attachments/assets/7cde128d-6599-4c71-835e-0fa89bcd4c98)

now we can perform the **known-plaintext attack** .

# Step 2: known-plaintext attack

now that we have all the files needed we can perform the known-plaintext attack to force the extraction of the content of the bin file .

first I needed to add the pkcrack to my system's PATH :

```bash
export PATH=$PATH:/home/Downloads/frim/pkcrack/bin
```

- first try :

```bash 
pkcrack -C 455ABUJ0C0.bin -c db/etc/zyxel/ftp/conf/system-default.conf -P plaintext.zip -p 455ABUJ0C0.conf 
```
-C 455ABUJ0C0.bin:

Specifies the encrypted ZIP file we want to crack. In this case, it is the file 455ABUJ0C0.bin.

-c db/etc/zyxel/ftp/conf/system-default.conf:

Specifies the target file inside the encrypted ZIP archive. pkcrack will attempt to crack the encryption for this specific file, which is located at the path db/etc/zyxel/ftp/conf/system-default.conf within the archive.

-P plaintext.zip:

Specifies a ZIP file containing a known plaintext version of a file. This is a critical part of the known-plaintext attack. pkcrack will compare the plaintext version with the encrypted file to deduce the encryption keys.

-p 455ABUJ0C0.conf:

Specifies the plaintext version of the file that corresponds to the target file (db/etc/zyxel/ftp/conf/system-default.conf) in the encrypted ZIP archive. The known plaintext must match the uncompressed contents of the encrypted file exactly.

![image](https://github.com/user-attachments/assets/5ca010a6-1d6e-4f94-9dc3-5c8b8b9159b4)

sadely it didn't work from the first try so we keeped looking for the problem. we ended up knowing that it might be the unzip method so we tried 

```bash
zip clear.zip 455ABUJ0C0.conf -9    
```
is because the plaintext file (455ABUJ0C0.conf) was compressed using the same settings as the original encrypted file, making it possible for pkcrack to succeed in its known-plaintext attack.

- second try :

```bash
pkcrack -C 455ABUJ0C0.bin -c db/etc/zyxel/ftp/conf/system-default.conf -P clear.zip -p 455ABUJ0C0.conf -d decrypt.zip -a
```

![image](https://github.com/user-attachments/assets/090a8e5a-d4e9-48e1-8dce-9e4d6914be6d)

reverse engineering done.

#step 3: Analysis of frimware source code 

after getting the cource code i srated by goign a bit traditional and looking for keywords like "password".

![image](https://github.com/user-attachments/assets/7691b0ba-2d31-4a3b-9b17-320592c0e2e7)

then started by looking file by file for the hash of the password.

we found the **compress.img** and to extract its content we used 

```bash
unsquashfs compress.img
```

This command created a directory named squashfs-root, which contained the extracted filesystem structure.

![image](https://github.com/user-attachments/assets/9b69ffe0-d9ea-4fe0-95c1-dab81876c840)

Navigating to the squashfs-root/etc directory revealed files such as passwd and shadow that might have the hash of the password.

and it did :

![image](https://github.com/user-attachments/assets/1530855b-deab-462e-95f8-db6be2a8a871)

an MD5-Crypt hash. The goal now is to crack this hash to retrieve the plaintext password.

# Final Step: Cracking the Hash

The $1$ prefix in the hash indicates that it uses the MD5-Crypt hashing algorithm.

## Cracking Process :

first we saved the hash into a file named hash.txt

```bash
echo '$1$k7T7lzsh$VwrIVeMWg5PYZoQmQLJmk1' > hash.txt
```
Then we defined the Known Password Characteristics:
It was known that the password started with PrOw!aN_fX and ended with one additional character.

and finally hashcat was used in mask attack mode to brute-force the final character of the password :

```bash
hashcat -m 500 -a 3 hash.txt PrOw\!aN_fX?1 --custom-charset1=?l?u?d?s
```

- -m 500: Specifies MD5-Crypt as the hash type.

- -a 3: Specifies a mask attack.

- hash.txt: Input file containing the hash.

- PrOw!aN_fX?1: Known part of the password, with ?1 representing the unknown character.

- --custom-charset1=?l?u?d?s: Limits the unknown character to lowercase, uppercase, digits, and special characters.

![image](https://github.com/user-attachments/assets/abde0792-add1-4f91-9ca9-b8378d8980a1)

![image](https://github.com/user-attachments/assets/e2938724-afba-4288-8ddd-2e7bc5f89fa2)


## Result

successfully cracked the hash :

```bash 
PrOw!aN_fXp
```

# Conclusion

This analysis and exploitation of CVE-2020-29583 reveal the dangers of hardcoded credentials within embedded systems. The systematic approach, involving firmware extraction, filesystem analysis, and hash cracking, underscores the importance of using robust security practices during development and deployment.

While the vulnerability provided an opportunity to showcase the use of tools like binwalk, unsquashfs, and hashcat, it also highlighted the challenges of troubleshooting and validating methodologies. Missteps, such as using incorrect plaintext files or mismatched compression settings, demonstrated the value of persistence and adaptability in the exploitation process.
