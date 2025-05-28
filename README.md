# Lab 3 – Memory Analysis Using Volatility

In this lab, I performed a forensic investigation on a captured memory file (`KobayashiMaru.vmem`) using Volatility, a memory analysis framework. The goal was to identify indicators of compromise, analyze suspicious processes, and understand how malware behaves in memory.

## 🧪 Objectives
- Identify OS and system configuration from a memory dump.
- Analyze running processes, network connections, and DLLs.
- Investigate potential malware behavior and evasion tactics.
- Correlate findings to construct a root cause timeline.

## 🔧 Tools Used
- Volatility Framework
- Windows XP memory image (`KobayashiMaru.vmem`)
- SANS Memory Forensics Cheat Sheet

## 🔍 Key Findings
- **OS Detected**: Windows XP Service Pack 2 (32-bit)
- **Suspicious Processes**:
  - `poisonivy.exe`: Known Remote Access Trojan (RAT)
  - `iroffer.exe`: Repeated instances, potentially malicious
  - `cryptcat.exe`: May indicate ransomware or encrypted comms
  - `nc.exe`: Netcat, used for data exfiltration
- **Network Connections**:
  - PID 1728 & 1480 → Local IRC communication on port 6667
  - PID 480 → External connection to `192.168.5.98:3460`
- **DLL Analysis**:
  - Malicious `poisonivy.exe` located in `System32` — suggests evasion
  - MalFind output detected injected code and rootkit activity (Hacker Defender)

## 🧠 Summary
This memory image shows strong signs of compromise via Poison Ivy RAT. The attacker appears to have leveraged backdoors, IRC channels, and rootkit techniques to maintain persistence and avoid detection. Volatility provided key insight into hidden processes, DLLs, and unauthorized access paths.

## 📂 Project Files

- 📄 Lab Instructions (PDF) - [ISCS-3523 Hunting in Memory Lab 3_Spring 2025 (2).pdf](https://github.com/user-attachments/files/20494526/ISCS-3523.Hunting.in.Memory.Lab.3_Spring.2025.2.pdf)
- 📄 My Full Analysis Report (PDF) - [Okuyiga_qvj870_3523_lab03.pdf](https://github.com/user-attachments/files/20494876/Okuyiga_qvj870_3523_lab03.pdf)

## 📚 References
- [Poison Ivy Trojan](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor%3AWin32%2FPoisonivy.I)
- [Hacker Defender Rootkit](https://www.f-secure.com/v-descs/rootkit-w32-hacdef.shtml)
- [Volatility Command Reference](https://code.google.com/archive/p/volatility/wikis/CommandReference22.wiki)
- [Cryptcat Overview](https://www.pcrisk.com/removal-guides/24737-cryptcat-ransomware)
[Okuyiga_qvj870_3523_lab03.pdf](https://github.com/user-attachments/files/20494876/Okuyiga_qvj870_3523_lab03.pdf)
