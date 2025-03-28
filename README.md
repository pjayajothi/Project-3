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
<a href="https://www.virustotal.com"><img src="https://img.shields.io/badge/-VirusTotal-394EFF?style=flat&logo=virustotal&logoColor=white" /></a>
<a href="https://gchq.github.io/CyberChef/"><img src="https://img.shields.io/badge/-CyberChef-0078D7?style=flat&logo=microsoft&logoColor=white" /></a>

## Steps
1. Find out- Who shared the malware samples?- from the first alert.
<img src="https://github.com/user-attachments/assets/3a366d85-3c3c-477f-871d-97f9fcf24dfc" alt="First Alert">
<img src="https://github.com/user-attachments/assets/fc9f8538-6a4c-4b95-a8b4-f68c8566c20e" alt="First Alert">
Ans: Oliver Bennett

2. What is the SHA1 hash of the file "pRsm.dll" inside samples.zip?
<img src="https://github.com/user-attachments/assets/d7472040-fbde-4f43-9f25-edc119af168a" alt="Attachment to examine">
<img src="https://github.com/user-attachments/assets/0876da89-4dd2-4b88-9c5d-063b78344f22" alt="Zip contents+ Hash Generation">
Ans: 9d1ecbbe8637fed0d89fca1af35ea821277ad2e8

3. Which malware framework utilizes these DLLs as add-on modules?
<br>To answer this(and the next few questions) we use the help of an article <a href="https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/">Evasive Panda APT group delivers malware via updates for popular Chinese software</a>
<img src="https://github.com/user-attachments/assets/14273605-2aaf-41d0-a265-3ad910c6ddf9" alt="Aticle used">
<img src="https://github.com/user-attachments/assets/9f766a4d-1807-4023-8f4e-9a3cbe8bbc98" alt="Relevant Section">
Ans: MgBot

4. Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?
<img src="https://github.com/user-attachments/assets/9602648c-c80b-46d3-9739-391853cf824f" alt="Relevant Section">
<img src="https://github.com/user-attachments/assets/7ea98e3e-b9b6-4746-b8e6-2665beb462e9" alt="Relevant Section">
Ans: T1123

5. What is the CyberChef defanged URL of the malicious download location first seen on 2020-11-02?
<img src="https://github.com/user-attachments/assets/87a6fd8c-149b-4cd4-9488-5de2ab95fec3" alt="CyberChef defanged URL">
<img src="https://github.com/user-attachments/assets/0bfba5c7-15ae-4a34-a30a-c897b0b721d3" alt="CyberChef defanged URL">
Ans: hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe

6. What is the CyberChef defanged IP address of the C&C server first detected on 2020-09-14 using these modules?
<img src="https://github.com/user-attachments/assets/c79acc8b-9710-46e7-8cc9-8bd5d75a3bc7" alt="CyberChef defanged IP">
<img src="https://github.com/user-attachments/assets/0199b7af-4b99-44e0-87fc-33ba30fbd25f" alt="CyberChef defanged IP">
Ans: 122[.]10[.]90[.]12

7. What is the SHA1 hash of the spyagent family spyware hosted on the same IP targeting Android devices on November 16, 2022?
<\n>To answer this we use the help of Virus Total:
<img src="https://github.com/user-attachments/assets/82648042-bb8e-43c6-9771-cab2689e6d3d" alt="First Alert">
<img src="https://github.com/user-attachments/assets/64f12cbc-1cbc-4182-b4f6-111909beea2e" alt="First Alert">
<img src="https://github.com/user-attachments/assets/9015e3d3-86ff-45ff-acde-9a4addfb534f" alt="First Alert">
<img src="https://github.com/user-attachments/assets/a2703f04-fb30-4c57-b2dd-d8b826d828c9" alt="First Alert">
Ans: 1c1fe906e822012f6235fcc53f601d006d15d7be


