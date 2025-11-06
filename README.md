# RTSP Scan

A multithreaded Python tool to **discover, test, and validate RTSP endpoints** across a network.  
It detects open and unauthenticated RTSP streams, supports credential brute-force attempts, 
can capture a single frame as a screenshot, and parses **Nmap XML output** for advanced targeting.

---

## 🚀 Features

- ✅ CIDR-based host discovery and threaded scanning  
- ✅ Nmap XML (`-oX`) import support  
- ✅ RTSP `DESCRIBE` and `OPTIONS` probing  
- ✅ Anonymous and credentialed connection testing  
- ✅ Multiple stream path attempts per host  
- ✅ Optional frame capture using OpenCV / Pillow  
- ✅ Threaded brute-force of username/password lists  
- ✅ Optional publish capability check (ANNOUNCE / RECORD)  
- ✅ Output-friendly console reporting  
- ✅ Lightweight dependencies (pure Python + OpenCV)

---

## 📦 Project Structure
```
RTSPScan/
├── rtsp_scan.py # main scanner script
├── rtspsocket.py # low-level RTSP DESCRIBE / OPTIONS / PUBLISH helpers
├── nmap_xml_reader.py # Nmap XML parser and target expander
├── userlist.txt # optional usernames for brute-force, retrieved from https://ipvm.com/reports/ip-cameras-default-passwords-directory
├── passlist.txt # optional passwords for brute-force, retrieved from https://ipvm.com/reports/ip-cameras-default-passwords-directory
├── streams.txt
└── README.md
```
---

## 🧰 Requirements

- Python 3.8+
- [OpenCV](https://pypi.org/project/opencv-python/) (`pip install opencv-python`)
- [Pillow](https://pypi.org/project/Pillow/) (optional, for screenshot saving)
- `argparse` (standard library)
- `xml.etree.ElementTree` (standard library)

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/rtsp-auditor.git
cd rtsp-auditor
pip install -r requirements.txt
```
---

## 🧭 Usage
### CIDR Scan Mode

Scan an entire subnet for RTSP streams:
```
python rtsp_scan.py --cidr 192.168.1.0/24 --stream-name live.sdp
```
### Nmap XML Mode

Feed results from an existing Nmap scan:
```
# Example Nmap scan
nmap -sV -p 554,8554 -oX cams.xml 192.168.1.0/24

# Run RTSP auditor on the XML
python rtsp_scan.py --nmap-xml cams.xml --stream-name live.sdp
```
### Username/Password Lists

Use brute-force with credential lists:
```
python rtsp_scan.py --cidr 10.0.0.0/24 \
    --userlist users.txt \
    --passlist passwords.txt \
    --threads 50
```

### Screenshot Capture

Save a snapshot from any stream that opens successfully:
```
python rtsp_scan.py --cidr 10.0.1.0/24 --screenshot-dir ./screens
```

### Skipping DESCRIBE (faster scan)
```
python rtsp_scan.py --cidr 10.0.0.0/24 --skip-describe
```

---

## ⚡ Output Example
```
[+] 192.168.1.15:554   → Open (no auth)
[+] 192.168.1.23:554   → Auth required
[-] 192.168.1.42:8554  → Closed or timeout
[!] 192.168.1.33:554   → Open but no frame
```

Screenshots (if enabled) are saved in the specified --screenshot-dir.

---
## 🧩 Integrating With Nmap

Run a full version/service scan:
```
nmap -sV -p 554,8554,10554,7070 -oX rtsp_scan.xml 10.0.0.0/24
```

Feed XML into RTSP Auditor:
```
python rtsp_scan.py --nmap-xml rtsp_scan.xml
```

The parser will automatically detect:

- Open RTSP-like services (service="rtsp")
- Common ports (554, 8554, etc.)
- Hostnames (if resolved)

## 🧠 Technical Notes
DESCRIBE phase: The scanner uses a lightweight RTSP handshake before attempting to fetch frames.

OpenCV capture: Only performed after a successful DESCRIBE, preventing long socket hangs.

Threading: Each IP/port/path combination is tested concurrently via ThreadPoolExecutor.

Brute-force: Usernames and passwords are tried per host in threaded batches.

Publish checks: Experimental ANNOUNCE / RECORD handshake support for rtsp-simple-server.

## ⚠️ Legal Disclaimer

This tool is provided for educational and authorized security auditing only.
Scanning or accessing RTSP devices without explicit permission may violate privacy or computer misuse laws.
Use responsibly and only within networks you own or are authorized to test.

## 🧑‍💻 Author

[@khr0x40sh](https://github.com/khr0x40sh)

## 🪪 License

MIT License — see [LICENSE](https://github.com/khr0x40sh/RTSPScan/blob/main/LICENSE)
 for details.

## TODO:
~~1. Create README.md~~

~~2. Implement nmap XML parsing capability~~

3. Implement reading hosts from a new-line delimited list

4. Fix check-publish feature

5. Implement check to read streams from RTSP options (if applicable).
