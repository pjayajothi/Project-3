# TryHackMe- Fridat Overtime

## Objective

Hello Busy Weekend. . .

It's a Friday evening at PandaProbe Intelligence when a notification appears on your CTI platform. While most are already looking forward to the weekend, you realise you must pull overtime because SwiftSpend Finance has opened a new ticket, raising concerns about potential malware threats. The finance company, known for its meticulous security measures, stumbled upon something suspicious and wanted immediate expert analysis.

As the only remaining CTI Analyst on shift at PandaProbe Intelligence, you quickly took charge of the situation, realising the gravity of a potential breach at a financial institution. The ticket contained multiple file attachments, presumed to be malware samples.

With a deep breath, a focused mind, and the longing desire to go home, you began the process of:

Downloading the malware samples provided in the ticket, ensuring they were contained in a secure environment.
Running the samples through preliminary automated malware analysis tools to get a quick overview.
Deep diving into a manual analysis, understanding the malware's behaviour, and identifying its communication patterns.
Correlating findings with global threat intelligence databases to identify known signatures or behaviours.
Compiling a comprehensive report with mitigation and recovery steps, ensuring SwiftSpend Finance could swiftly address potential threats.
Connecting to the machine

Start the virtual machine in split-screen view by clicking the green Start Machine button on the upper right section of this task. If the VM is not visible, use the blue Show Split View button at the top-right of the page. Additionally, you can open the DocIntel platform using the credentials below.  

## Skills Learned
This CTF room focuses on Cyber Threat Intelligence (CTI) and Malware Analysis skills. Here’s what you can expect to learn:

1. Malware Handling & Analysis
Securely downloading malware samples and ensuring containment in a sandboxed environment.

Preliminary automated malware analysis using tools like VirusTotal, Any.Run, or hybrid-analysis.com.

Manual malware analysis using static and dynamic techniques (e.g., strings analysis, behavioral analysis).

2. Threat Intelligence & Correlation
Identifying Indicators of Compromise (IOCs) from malware samples.

Matching findings with global threat intelligence databases to determine if the malware is known or new.

Understanding malware communication patterns (e.g., C2 servers, domain lookups).

3. Incident Response & Mitigation
Compiling an investigative report summarizing malware characteristics, potential damage, and recommended mitigation steps.

Suggesting recovery steps for an affected financial institution.

Implementing threat-hunting techniques to detect similar threats in the network.

4. Hands-on with Threat Intel Platforms
Using DocIntel or other CTI platforms to analyze and manage threat data.

Enriching intelligence reports by correlating malware signatures with past incidents.
This CTF is ideal for building practical threat intelligence and malware analysis experience, which can be valuable for roles in SOC analysis, CTI, digital forensics, and incident response.

### Tools Used
<a href="https://tryhackme.com"><img src="https://img.shields.io/badge/-TryHackMe-212C42?style=flat&logo=tryhackme&logoColor=white" /></a>


## Steps
1. Find out- Who shared the malware samples?- from the first alert.
Ans: Oliver Bennett

2. What is the SHA1 hash of the file "pRsm.dll" inside samples.zip?
Ans: 9d1ecbbe8637fed0d89fca1af35ea821277ad2e8

3. Which malware framework utilizes these DLLs as add-on modules?
Ans: MgBot

4. Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?
Ans: T1123

5. What is the CyberChef defanged URL of the malicious download location first seen on 2020-11-02?
Ans: hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe

6. What is the CyberChef defanged IP address of the C&C server first detected on 2020-09-14 using these modules?
Ans: 122[.]10[.]90[.]12

7. What is the SHA1 hash of the spyagent family spyware hosted on the same IP targeting Android devices on November 16, 2022?
Ans: 1c1fe906e822012f6235fcc53f601d006d15d7be

