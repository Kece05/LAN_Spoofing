# FloodLAN - Local Area Network Scanner & DoS Tool

FloodLAN is a Python script that allows you to scan your local area network for connected devices and perform Denial of Service (DoS) attacks on specific devices.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Disclaimer](#disclaimer)
- [Future Ideas](#ideas)

## Features

- Scan your local network for connected devices.
- Display IP addresses, MAC addresses, company names, and device names (if available) of connected devices.
- Perform a Denial of Service (DoS) attack on a specific device.
- Interactive menu for easy navigation.

## Requirements
- MacOS
- Python 3.x
- Additional Python packages:
  - scapy
  - mac_vendor_lookup
  - pyfiglet

You can install the required packages using the following command:
  pip3 install scapy mac-vendor-lookup
  
***You'll also need administrative privileges in order to run this file***

## Installation

1. ***Clone this repository to your local machine:*** git clone https://github.com/Kece05/FloodLAN.git
3. ***Navigate to the FloodLAN directory:*** cd Network
5. ***Run the FloodLAN script:*** sudo python3 FloodLan.py


## Usage

1. When you run the script, you will see a main menu with the following options:

   - **Scan network devices**: This option will scan your local network for connected devices and display the results.

   - **DoS Attack on a device**: This option allows you to perform a DoS attack on a specific device. You will need to choose a number from the list of scanned devices to target.

   - **Help**: Provides helpful information about using the FloodLAN tool.

   - **Exit**: Allows you to exit the FloodLAN tool.

2. Choose an option from the menu using the corresponding number.

3. Follow the on-screen instructions to perform network scanning or DoS attacks.

## Disclaimer

- Performing DoS attacks without proper authorization is illegal and unethical. This tool is intended for educational and authorized testing purposes only.

- The displayed company names might not always be accurate, as the MAC address vendor lookup database might not have the latest information.

- Some devices may have custom MAC addresses, leading to unidentified results. Use this information as a reference but not as the sole basis for device identification.

- Always verify device details through other means for critical assessments.

## Ideas
- Create Bluetooth Attacks(BlueSmarfing, Bluesnarfing, Bluebugging)(Very difficult on MacOS)
- Network mapping
- Support Different Platforms
- Port Scanning
- Vulnerability Wifi Scanning
