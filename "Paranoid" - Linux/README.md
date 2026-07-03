# Overview: 
**We are provided with Linux audit logs from a compromised endpoint, and we need to analyze the logs to answer the prompt questions to ultimately find out the steps and techniques used by the attacker.**

<br> 

![Inv](screenshots/0.png)

### Methodology: 
**This is another challenge where we are tasked with manually sifting through the log file without any sort of SIEM or logging aggregate tool, so this time we will use bash to analyze the logs.**

---

<br>

### Attack Chain:
                                            Brute force SSH login attempts (btlo account)
                                                                 ↓
                                                 Successful login from 192.168.4.155
                                                                 ↓
                                                LinPEAS downloaded and run (enumeration)
                                                                 ↓
                                                evil.tar.gz downloaded (same attacker IP)
                                                                 ↓
                                            C source compiled into "evil" binary (collect2/ld)
                                                                 ↓
                                                  evil binary executed (pid 829992)
                                                                 ↓
                                                  Targets sudoedit - CVE-2021-3156
                                                                 ↓
                                                  Heap-based buffer overflow triggered
                                                                 ↓
                                                     Root access gained (euid=0)
                                                                 ↓
                                                  /etc/shadow read and exfiltrated
                                            
---

<br>

## Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| IP Address | 192.168.4.155 | SSH brute-force source; also hosted linpeas and evil.tar.gz for download |
| Filename | evil.tar.gz | Archive containing exploit source code, downloaded from attacker IP |
| Filename/Binary | evil | Compiled exploit binary; executed to trigger CVE-2021-3156 (pid 829992) |
| Tool/Filename | linpeas.sh | Enumeration script downloaded and run for privilege escalation recon |
| CVE | CVE-2021-3156 | "Baron Samedit" - heap-based buffer overflow in sudo, exploited via sudoedit |
| File Path | /etc/shadow | Sensitive credential file accessed and exfiltrated post-compromise |

---

<br> 

## MITRE ATT&CK Mapping

| ATT&CK ID | Technique | Evidence |
|---|---|---|
| T1110 | Brute Force | Repeated failed SSH login attempts against `btlo` account from 192.168.4.155, followed by successful login |
| T1078 | Valid Accounts | Attacker authenticated using legitimate (brute-forced) credentials for `btlo` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Shell commands executed to download/run linpeas and the `evil` binary |
| T1082 | System Information Discovery | LinPEAS run to enumerate system configuration and privilege escalation paths |
| T1518 | Software Discovery | LinPEAS enumeration of installed software/versions, including sudo versoin |
| T1587 / T1583 | Develop Capabilities / Compromise Infrastructure | `evil.tar.gz` staged on attacker-controlled host; C source compiled locally into `evil` binary |
| T1068 | Exploitation for Privilege Escalation | `evil` binary exploited CVE-2021-3156 (heap-based buffer overflow) via `sudoedit` to gain root |
| T1548 | Abuse Elevation Control Mechanism | Sudo mechanism specifically abused to escalate from local user to root |
| T1003 | OS Credential Dumping | `/etc/shadow` read directly to obtain password hashes |

---

<br> 

## Investigation:

### 1. What account was compromised?

For this one we know it's an account being compromised and not a device, so my first thought is to check for attempted logins: 
![Q1](screenshots/1.png)

We can see many successive failed attempts separated by seconds/milliseconds almost certainly indicating a brute force attack over SSH, then we finally see a successful attempt with a timestamp of 1633393393.365:467550 (October 4th 2021):
![Q1](screenshots/2.png)

We see here the account compromised is "btlo".


**Answer: btlo**

---


### 2. What attack type was used to gain initial access?
We see from above that the attack is brute force over SSH!

**Answer: Brute Force**

---

### 3. What is the attacker's IP address?
We see in the successful login log that the attacker's IP is 192.168.4.155!

**Answer: 192.168.4.155**

---

### 4. What tool was used to perform system enumeration?
For this I'm going to search for command line execution that inlcudes common enumeration tools (netcat, linpeas, nmap, etc.): 

```bash
grep -i 'linpeas\|nmap\|wget\|curl\|python\|perl\|ruby\|netcat' audit.log:
```

![Q4](screenshots/3.png)

We can see in Event 468451 that linpeas is downloaded, and we can see in Event 468664 (and events after) linpeas being run and scanning different directories in the system.
**Answer: linpeas**

---

### 5. What is the name of the binary and pid used to gain root?
For this we see that a gzip file called evil.tar.gz was downloaded from the same IP (attacker IP) that linpeas was downloaded from:
![Q5](screenshots/4.png)

We will look more into that with the command:

```bash
grep 'type=EXECVE' audit.log | grep 'evil\|tar'
```
![Q5](screenshots/5.png)

We see a binary called "evil" being compiled with collect2 and ld (C code compiler tools), so let's check related SYSCALL logs after evil was created where euid == 0 (means user ID is root): 
![Q5](screenshots/6.png)

In the very next event (ID = 481022) we see a successful "sudoedit" with euid = 0 and pid=829992, meaning evil found a vulnerability within sudoedit that allowed for root privilege escalation. 
**Answer: evil, 829992**

---

### 6. What CVE was exploited to gain root access? (Do your research!) 
The CVE exploited was CVE-2021-3156 (nicknamed "Baron Samedit") - which is a heap buffer overflow in sudo triggered by sudoedit that allows for root access and affects any local user regardless of sudo privileges. 
**Answer: CVE-2021-3156**

---

### 7. What type of vulnerability is this? 
*Answered above*

**Answer: Heap-Based Buffer Overflow**

---

### 8. What file was exfiltrated once root was gained? 
For this one we are going to filter for PATH logs after root access was gained to check where files were catted, opened/read, etc:

```bash
grep 'type=PATH' audit.log | awk -F: '{if ($2 > 481036) print}' | head -20
```

![Q8](screenshots/7.png)

We see event 481063 is catting a file, but it doesn't say what that file is, so we will need to check the EXECVE log for that event: 

```bash
grep 'type=EXECVE' audit.log | grep '481063'
```

![Q8](screenshots/8.png)

We can see here the file catted is "/etc/shadow" which holds all of the hashed passwords only accessible by root - this is the file that was exfiltrated!

**Answer: /etc/shadow**

---

**Completed:**
![Q8](screenshots/complete.png)
