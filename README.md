# TrafficShield 🛡️

Advanced DDoS protection library to detect and mitigate botnet attacks (Mirai-style). Single-file, easy to integrate.

## Features
- Rate limiting (per IP, adaptive)
- Botnet beaconing detection
- Mirai signature-based detection (UDP flood, SYN flood)
- IP blacklisting
- CAPTCHA challenge placeholder
- Flask integration example

## Installation

Just copy `trafficshield.py` into your project.

```bash
pip install flask  # if you want the example
