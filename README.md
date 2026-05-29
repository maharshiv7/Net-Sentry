# Net-Sentry v3.0 🛡️

Net-Sentry is an enterprise-grade cybersecurity recon toolkit built with a Python backend and a responsive Vanilla JS/Tailwind frontend. It features a tactical ARP network scanner, multi-threaded port scanning, WebRTC IP leak detection, and advanced DNS record sniping. It also generates automated 1-click security audit reports for real-time threat intelligence.

NOTICE:Net-Sentry is developed strictly for educational purposes and ethical network administration. Do not use this tool to scan networks or target domains without explicit authorization from the network owner. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.



## 🚀 Key Features

* **Tactical ARP Network Scanner:** Discovers active devices on the local subnet, resolves hostnames, and identifies randomized MAC addresses using `scapy`.
* **Multi-Threaded Port Scanner:** Rapidly checks discovered network nodes for open critical ports (SSH, HTTP, FTP, SMB, etc.) using Python `socket`.
* **WebRTC Stealth Checker:** A purely client-side script that provokes STUN servers to detect underlying IP leaks, bypassing active VPNs.
* **Target Domain Recon (DNS Sniper):** Interrogates global DNS servers to extract hidden records (A, AAAA, MX, NS, TXT) for any target domain using `dnspython`.
* **Device Fingerprinting & OpSec Analysis:** Analyzes browser connection leaks (User-Agent, DNT headers), evaluates password entropy, and calculates a network privacy score.
* **1-Click Audit Report:** Compiles all discovered public identity logs, fingerprints, and network nodes into a downloadable `.txt` security audit report.

## 💻 Tech Stack

* **Backend:** Python 3, Flask, Flask-CORS
* **Networking/Security Libraries:** `scapy` (Packet manipulation), `socket` (Port scanning), `dnspython` (DNS resolution)
* **Frontend:** HTML5, Vanilla JavaScript, Tailwind CSS, FontAwesome

## ⚙️ Prerequisites

To run the backend network scanner properly, your system must allow the sending of raw packets.
* **Windows:** You must run your terminal/command prompt as **Administrator**.
* **Linux/macOS:** You must run the Python script using **sudo**.

## 🛠️ Installation & Setup

1. **Clone the repository:**
```bash
   git clone [https://github.com/maharshiv7/net-sentry.git](https://github.com/maharshiv7/net-sentry.git)
   cd net-sentry
   pip install flask flask-cors scapy dnspython
   python app.py```



