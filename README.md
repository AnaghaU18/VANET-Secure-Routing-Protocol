# Secure VANET Protocol Simulation

## Overview
This project simulates a **secure routing protocol for Vehicular Ad Hoc Networks (VANETs)**, focusing on robust message authentication, integrity, and attack detection. The protocol leverages digital signatures (ECDSA) and multiple salted hash functions to protect inter-vehicle communication against replay, Sybil, and data tampering attacks. Vehicle mobility is modeled using realistic traces from SUMO FCD XML files.

## Features
- **Realistic Mobility:** Integrates SUMO Floating Car Data (FCD) XML for vehicle movement.
- **Cryptographic Security:** Each vehicle uses ECDSA digital signatures and multiple hash algorithms (SHA256, MD5, SHA1, Blake2b, SHA3-256) with per-vehicle salt.
- **Attack Detection:** Detects and logs replay attacks, Sybil attacks, and data tampering.
- **Performance Metrics:** Computes and visualizes Packet Delivery Ratio (PDR), end-to-end delay, throughput, and security event statistics.
- **Visualization:** Plots PDR over time and end-to-end delay for received messages.

## Requirements
- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)
- matplotlib
Install dependencies with: pip install cryptography matplotlib

## Usage
1. **Prepare Mobility Data:**  
   Place your SUMO FCD XML file (e.g., `simple_fcd.xml`) in the same directory as `src.py`.
2. **Run the Simulation:**
    python src.py
3. **Output:**  
- Simulation statistics are printed in the terminal, including total packets sent/received, PDR, delay, throughput, and security events.
- Two plots are displayed:
  - **PDR over Time**
  - **End-to-End Delay of Received Packets**

## How It Works
- **Vehicle Initialization:**  
Each vehicle is assigned a unique ID, cryptographic key pair, and salt.
- **Message Generation:**  
At each timestep, vehicles broadcast messages containing their ID, position, speed, and timestamp. Each message is hashed (with salt) and signed.
- **Message Verification:**  
Receivers verify message integrity (hashes), authenticity (signature), freshness (replay cache), and sender identity (Sybil check).
- **Metrics and Logging:**  
Successful and failed messages are tracked for performance and security analysis.
