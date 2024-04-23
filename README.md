# Network Security Analysis and Intrusion Prevention System (IPS) Implementation

## Objective

The objective of this project is to enhance network security by implementing and configuring an Intrusion Prevention System (IPS) using Snort. The project aims to understand, simulate, and detect various types of cyber attacks, including brute force, SQL injection, TCP SYN flood, Ping of Death, and Slowloris attacks, thereby demonstrating the effectiveness of the IPS and the importance of robust network security configurations.

### Skills Learned

- **Network Security:** Understanding of various types of cyber attacks and how to detect and mitigate them.
- **Intrusion Detection and Prevention Systems (IDS/IPS):** Experience with configuring and using IDS/IPS tools like Snort or Suricata on pfsense.
- **Firewall Configuration:** Knowledge of how to configure firewall rules and settings to improve network security.
- **Packet Analysis:** Ability to use tools like Wireshark to analyze network traffic and detect anomalies.
- **Penetration Testing:** Experience with conducting controlled attacks on a system to test its security, using tools like hping3 and slowhttptest.
- **Cybersecurity Tools:** Proficiency in using various open-source cybersecurity tools (SQLmap, Burpsuite).
- **Technical Documentation:** Ability to document technical processes, findings, and recommendations clearly and effectively.

### Tools Used

- **Snort or Suricata:** Open-source Intrusion Prevention Systems (IPS) for detecting and preventing cyber attacks.
- **pfSense:** An open-source firewall that provides robust network security features.
- **hping3:** A network tool used to craft TCP/IP packets, used in your project for simulating DDoS attacks.
- **Hydra** A brute-forcing tool used to bruteforce SSH credentials.
- **slowhttptest:** A tool used to simulate Slowloris attacks.
- **Wireshark:** A network protocol analyzer used for understanding the network traffic and detecting anomalies.
- **SQLmap:** An open-source penetration testing tool that automates the detection and exploitation of SQL injection flaws.
- **OWASP Juice Shop:** An intentionally insecure web application used for security training and testing.

## Steps

### Network Diagram

This is the Network Diagram for this Project. I have implemented Snort on pfsense WAN and DMZ interfaces and will launch attacks from the Console machine residing under LAN.

![Final+Project drawio](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/2bd39090-31f0-4672-ba3f-ecbd4554394f)

### Configuration

OWASP JuiceShop is hosted on DMZ interface. I have configured NAT to redirect traffic to Juiceshop on both 22(SSH) and HTTP(80) protocols. NAT IP is a redirect IP that is set to the Juiceshop server IP address. So any traffic on pfsense WAN IP will redirected to Juiceshop in DMZ. This configuration will allow us to simulate External attacks on Juiceshop.

![Screenshot 2024-04-23 165105](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/3f2ff2a2-e475-4aad-9ee1-2b4315e24ea3)

I have followed the official documentation from Netgate for<a href="https://docs.netgate.com/pfsense/en/latest/packages/snort/setup.html"> Configuring the Snort on pfsense.</a> Now, we are ready to detect common attacks using Snort rules.

### Launch and Detect SQL Injection attack (External)

Used sqlmap to automate the SQL injection againts Juiceshop login page. IP address used in command is belong to WAN interface of pfsense, demonstrating the attack is coming from External machine. I have created a basic Snort rules that detects common sql parameters(' or 1=1, union, or--) in http requerst sent to Juiceshop, which is common signs of SQL Injection attack.   

![Screenshot 2024-04-10 150925](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/78046bd6-d87e-4f3f-9598-03ca570f0692)

- **Snort Signatures that detected alerts:**
  1. *alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg: "Error Based SQL Injection Detected"; content: "%27"; sid:100000011;)*
  2. *alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg: "Error Based SQL Injection Detected"; content: "22"; sid:100000012;)*
  3. *alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg: "AND SQL Injection Detected"; content: "and"; nocase; sid:100000013;)*
  4. *alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg: "OR SQL Injection Detected"; content: "or"; nocase; sid:100000014;)*
  5. *alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg: "UNION SELECT SQL Injection"; content: "union"; sid:100000017;)*

- **Snort Alerts on pfsense**

![Screenshot 2024-04-10 151057](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/7c2860e9-67ad-437d-956c-6a2e17773833)

### Launch and Detect SSH brute-force attack (External)

Used Hydra to brute-force SSH credentials againts Juiceshop. This time I configured Snort in Blocking mode to test real-time intrusion prevention by autometically blocking hosts that sending malicious traffic. Below is the command I used to launch brute-force attack. The rule will trigger an alert if it detects more than 5 attempts to start a TCP connection to the SSH port on the home network from the same source within a 30 second period. It is recommanded to adjust the threshold values to avoid false positives. It often requires a bit of trial and error, and a good understanding of the normal network traffic patterns and the nature of the attacks you’re trying to detect.

![Screenshot 2024-04-11 232030](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/7d5dec59-030f-4a18-9970-7584de274148)

- **Snort Signatures that detected alerts:**
  1. *alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH brute forcing!"; flags: S+; threshold: type both, track by_src, count 5, seconds 30; sid:100000018;)*
    
- **Snort Alerts on pfsense**

![Screenshot 2024-04-11 231815](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/bfb08af0-4e0f-4903-86f1-af5b626bdb8a)
![Screenshot 2024-04-12 000427](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/0072280c-578a-44f3-ac05-3c8611e4fbff)

### Launch and Detect TCP SYN Flood attack (Internal)

Used Hping3 to simulate a TCP SYN flood. This attack flood the target IP with SYN packets causing denial-of-service. **--flood** sends packets as fast as possible.
**-S** sets the SYN flag, indicating the start of a TCP connection.
**-p 80** specifies the target port (in this case, 80).
**--rand-source** uses random source IP addresses for each packet, making it harder for the target to block the attack. The Snort rule will look for TCP packets with only SYN flag is set **(flags: S)** regardless of state of the connection **(flow: stateless)** and only trigger if it sees more than 1000 connection attempts **(count 1000)** to the same destination **(track by_dst)** within a 20 second period **(seconds 20)**. 

![Screenshot 2024-04-12 180328](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/d8131421-ea33-43e8-83e2-6da82840605d)

- **Snort Signatures that detected alerts:**
1. *alert tcp any any -> $HOME_NET 80 (msg: “TCP SYN Flood attack detected”; flags: S; flow: stateless; threshold: type both, track by_dst, count 1000, seconds 20; sid:100000019; classtype:attempted-dos;)*

- **Snort Alerts on pfsense**

![Screenshot 2024-04-12 180259](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/e8398b37-2d2c-4b98-aea8-903b24d4c36a)

### Launch and Detect Ping of Death attack (External)

Configured Snort in Blocking mode and used Hping3 to simulate an ICMP Ping of Death attack. This attack floods the target IP with oversized ICMP packets causing potential buffer overflow and denial-of-service. Below is the command I used to launch DoS attack. **-1** or **--icmp** is used to set the ICMP mode. **-d 65000** sets the packet size to 65000 bytes, which is larger than the normal ICMP packet, causing fragmentation and potential buffer overflow on the target system. The Snort rule will look for ICMP packets with type 8 (echo request) (itype:8) that are larger than 10000 bytes (dsize:>10000) regardless of the state of the connection (flow: stateless) and only trigger if it sees more than 10 such packets (count 10) to the same destination (track by_dst) within a 20 second period (seconds 20).

![Screenshot 2024-04-12 191937](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/14379301-8c57-4217-9f1d-b25c48103f97)

- **Snort Signatures that detected alerts:**
1. *alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg: “ICMP Ping of Death attack detected”; itype:8; dsize:>10000; threshold: type both, track by_dst, count 10, seconds 20; sid:100000019; classtype:attempted-dos;)*

- **Snort Alerts on pfsense**

![Screenshot 2024-04-12 191809](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/8328c9db-fef7-4e96-9050-bcd5aaaa9a20)
![Screenshot 2024-04-12 191852](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/c04701ce-8254-49cd-ab37-d708de7b5e68)
![Screenshot 2024-04-12 191736](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/3cda1dfa-6c46-48d0-87af-f7606ad55e2d)

### Launch and Detect Slowloris attack (External)

A slowloris is layer-7 DDoS attack involves sending a lot of partial HTTP requests and keeps connections open for as long as possible, and eventually causing denial-of-service. I used the **slowhttptest** kali tool to demonstrate the attack. The target is pfsense WAN IP (Attacking Juiceshop Externally). Below is the command I used to launch Slowloris attack. It opens 500 new connections to the target server every second **(-r 500)**, with each connection sending an HTTP GET request with a header of 24 bytes **(-x 24)** every 10 seconds **(-i 10)**. 

![Screenshot 2024-04-18 163805](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/21c65bcf-9843-4d68-b928-01e1b039dfbc)
![Screenshot 2024-04-17 193740](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/e9176c41-61fc-4004-89a9-f63ef3cac09d)

Detecting these type of attack is quite challanging as it operates by sending HTTP request which are similar to legitimate client requests. It maintains many connections to the target server by continuously sending incomplete headers. This behavior does not generate unusual traffic patterns and often flies under the radar of many intrusion detection systems, as it does not trigger typical threshold-based alerts. Hence, to detect these attack I analysed the HTTP traffic using wireshark and found that tool specifically uses random payload while sending keep alive packets, that starts with **'X-'** and size of these payloads are below **50 bytes**. I used this information to create a Snort rule which trigger an alert if it detects more than 200 small packets containing “X-” in payload going to port 80 on the home network from the same source within a 10 second period, which could indicate a possible Slowloris DoS attack. This rule is designed to specifically detect attacks launch by slowhttptest. It might not detect same attack launched via diffrent tool. 

![Screenshot 2024-04-23 201616](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/140b9088-ecb5-4317-9cea-349a3e7e8182)

- **Snort Signatures that detected alerts:**
1. *alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SlowLoris DoS attempt"; flow:established,to_server,no_stream; content:"X-"; dsize:<50; threshold: type both, track by_dst, count 200, seconds 10; sid:100000020; classtype:denial-of-service;)*

- **Snort Alerts on pfsense**

![Screenshot 2024-04-17 193901](https://github.com/JP-Portfolio/IDS-LAB/assets/167912526/65a61f2c-2c02-4898-9e01-6564e6c89337)
