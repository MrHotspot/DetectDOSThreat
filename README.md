---

# Detect Threat 

## Overview

Detect Threat is a Python script designed to monitor network traffic and detect potential Denial of Service (DoS) attacks by analyzing TCP SYN packets. It utilizes the Scapy library for packet sniffing and inspection.

When running, the script continuously listens for incoming TCP SYN packets on a specified network interface. If it detects multiple SYN packets from the same source IP address within a 10-second window, it raises an alert, indicating a potential DoS attack.

## Requirements

- Python 3.x
- Scapy library
  ```
  pip install scapy
  ```

## Usage

1. **Clone Repository**: Clone this repository to your local machine.
   ```
   git clone https://github.com/your_username/detect-threat.git
   ```

2. **Navigate to Directory**: Navigate to the directory containing the script.
   ```
   cd detect-threat
   ```

3. **Run the Script**: Execute the script using Python.
   ```
   python detect_threat.py
   ```

4. **Provide Interface Name**: The script will prompt you to enter the name of the network interface you want to monitor. This interface should be the one connected to the network you wish to monitor (e.g., eth0, wlan0).

5. **Monitor for Attacks**: Once you've provided the interface name, the script will start monitoring traffic on that interface. It will analyze incoming TCP SYN packets and raise an alert if it detects multiple SYN packets from the same source IP address within a 10-second window.

6. **Terminate**: To stop the script, press `Ctrl + C` in the terminal.

## Notes

- Ensure that you have necessary permissions to access network interfaces. You may need to run the script with elevated privileges (e.g., using `sudo`).
- This script is intended for educational and testing purposes. Use it responsibly and avoid using it on networks without proper authorization.

---
