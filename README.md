# CodeAlpha Internship Tasks Overview

## Introduction
This README provides an overview of the tasks completed during my internship at CodeAlpha. These tasks focus on practical applications in cybersecurity, including building a network sniffer, developing a phishing awareness training module, and conducting a secure coding review. Each task was aimed at enhancing my technical skills, understanding vulnerabilities, and promoting best practices in software security.

---

## 1. Network Sniffer
### Description
The network sniffer was developed as part of my task to capture and analyze network traffic in a local network environment. This tool was implemented in Python using libraries such as `scapy`, allowing me to intercept packets and display relevant information like IP addresses, protocols, and packet payloads.

### Key Features
- **Packet Capture**: Captures incoming and outgoing network packets.
- **Protocol Analysis**: Identifies and displays details about various network protocols.
- **Payload Extraction**: Extracts and decodes payload data for analysis.

### Code Example
```python
from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Packet from {packet[IP].src} to {packet[IP].dst} with protocol {packet.proto}")

sniff(prn=packet_callback, store=0)
```

---

## 2. Phishing Awareness Training
### Description
As part of raising awareness about cybersecurity threats, I created an interactive phishing awareness presentation in PowerPoint. This presentation included real-world examples of phishing scams, techniques used by attackers, and best practices for recognizing and avoiding these threats.

### Key Points
- **Understanding Phishing**: Explanation of what phishing is and how it works.
- **Examples of Phishing Attacks**: Screenshots and descriptions of typical phishing emails and websites.
- **Prevention Tips**: Tips on how to identify suspicious emails and stay safe online.
- **Interactive Quiz**: A brief quiz to reinforce learning.

---

## 3. Secure Coding Review
### Description
The secure coding review involved analyzing and reviewing a vulnerable Java application (`VulnerableWebApp`). I assessed the code for common vulnerabilities such as SQL injection, XSS, hardcoded credentials, and insecure password storage. This task also included developing a secure version of the code and providing detailed recommendations.

### Key Points
- **Vulnerabilities Identified**:
  - **SQL Injection**: Directly concatenating user inputs into SQL queries.
  - **XSS**: Displaying user inputs without sanitization.
  - **Hardcoded Credentials**: Storing credentials directly in the source code.
  - **Insecure Password Storage**: Displaying passwords in plaintext.

- **Recommendations**:
  - Use **parameterized queries** or **prepared statements** to prevent SQL injection.
  - **Hash passwords** with algorithms like bcrypt.
  - Avoid **hardcoding credentials**; use environment variables or secure configuration.
  - **Sanitize user inputs** to mitigate XSS.

### Secure Code Implementation Example
```java
// Secure SQL Query with PreparedStatement
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();
```

---

## Conclusion
These tasks during my internship at CodeAlpha have significantly improved my practical cybersecurity skills. By building a network sniffer, creating phishing awareness content, and reviewing code for security vulnerabilities, I have gained a comprehensive understanding of common threats and best practices for secure development.

---

