# Snep Prowler ^. .^ Build Sheet & Operation Guide

## 1. Hardware Specifications & Components

- **Microcontroller**: ESP32 Development Board (ESP32-WROOM / Generic Node)
- **Display**: 0.96-inch SSD1306 I2C OLED Display (128x64 resolution, Address: `0x3C`)
- **Input Device**: M5Stack CardKB V2 Unit (I2C interface, Address: `0x5F`)
- **Storage**: Internal Flash partitioned with LittleFS file system for persistent logging (<span style="color: #B19CD9;">/packet_log.txt</span>)

## 2. Pinout & Wiring Mapping

| Component | ESP32 Pin | Connection Details |
| :--- | :--- | :--- |
| **I2C SDA** | GPIO 17 | Shared line connected to OLED SDA and CardKB V2 SDA |
| **I2C SCL** | GPIO 18 | Shared line connected to OLED SCL and CardKB V2 SCL |
| **Power (VCC)** | 3.3V / 5V | Regulated power rail matching module specifications |
| **Ground (GND)** | GND | Common system ground |

## 3. Software Dependencies & Libraries

- **Core Architecture**: ESP32 Arduino Core v3.x / IDF v5.x
- **Display & UI Libraries**:
  - `Wire` (Built-in I2C communication)
  - `Adafruit_GFX` (Core graphics library)
  - `Adafruit_SSD1306` (OLED display controller)
- **Wireless & Networking**:
  - `WiFi.h` & `esp_wifi.h` (Wi-Fi operational modes, channel hopping, AP frame injection)
  - `esp_now.h` (Serverless peer-to-peer radio messaging protocol)
  - `BLEDevice.h`, `BLEScan.h`, `BLEAdvertising.h` (Bluetooth Low Energy management)
- **System Utilities**:
  - `LittleFS.h` (Flash file management for persistent logging)
  - `<vector>`, `<algorithm>` (Standard Template Library containers)

## 4. Global Navigation & General Controls

- **Main Menu**: Use <span style="color: #B19CD9;">[o]</span> (Up) and <span style="color: #B19CD9;">[k]</span> (Down) to highlight options. Press <span style="color: #B19CD9;">[Enter]</span> to select.
- **Exit / Return**: Press <span style="color: #B19CD9;">[q]</span>, <span style="color: #B19CD9;">[Q]</span>, or <span style="color: #B19CD9;">[ESC]</span> from any active mode or detail screen to stop transmissions and return to the previous view or main menu.

## 5. Function & Module Operation Instructions

1. **IoT Terminal**
   - Type commands using the CardKB V2 and press <span style="color: #B19CD9;">[Enter]</span> to transmit over Serial (115200 baud).
   - Press <span style="color: #B19CD9;">[&#96;]</span> (backtick) to switch sub-modes between TX, RX history inspection, and quick macros.
   - Use <span style="color: #B19CD9;">[o]</span>/<span style="color: #B19CD9;">[k]</span> to scroll through command history or incoming serial responses. Press <span style="color: #B19CD9;">[c]</span> to clear RX logs.

2. **Wi-Fi Scanner**
   - Automatically scans surrounding access points. Use <span style="color: #B19CD9;">[o]</span>/<span style="color: #B19CD9;">[k]</span> to scroll through the list.
   - Press <span style="color: #B19CD9;">[Enter]</span> on a network to view parameter details (RSSI, channel, BSSID MAC, encryption).
   - Press <span style="color: #B19CD9;">[s]</span> to append the network log to internal flash storage.

3. **Packet Monitor**
   - Displays a real-time scrolling histogram graph showing activity percentage and packet counters.
   - Use <span style="color: #B19CD9;">[o]</span>/<span style="color: #B19CD9;">[k]</span> to change channels (1-13). Changing channels resets the packet counter.

4. **ESP Now Chat**
   - Decentralized peer-to-peer radio messaging. Type text and press <span style="color: #B19CD9;">[Enter]</span> to broadcast to peers on the active channel.
   - Press <span style="color: #B19CD9;">[&#96;]</span> to cycle communication channels (1-13).
   - Use <span style="color: #B19CD9;">[+]</span> and <span style="color: #B19CD9;">[-]</span> keys to scroll up and down through message history without occupying typing characters <span style="color: #B19CD9;">[o]</span> and <span style="color: #B19CD9;">[k]</span>.

5. **BLE Beacon**
   - Type a custom string on the keyboard and press <span style="color: #B19CD9;">[Enter]</span> to spin up a BLE advertisement beacon broadcasting that exact name.

6. **BLE Scanner**
   - Scans surrounding BLE peripherals. Use <span style="color: #B19CD9;">[o]</span>/<span style="color: #B19CD9;">[k]</span> to navigate and <span style="color: #B19CD9;">[Enter]</span> to view details (MAC, RSSI, manufacturer ID). Press <span style="color: #B19CD9;">[s]</span> to save to flash.

7. **Beacon Spam**
   - Cycles multi-vendor BLE beacon profiles (AirTags, smart devices, audio gear). Press <span style="color: #B19CD9;">[Enter]</span> to toggle active/idle.

8. **WiFi Spammer**
   - Broadcasts fake AP beacon frames mimicking popular public networks. Press <span style="color: #B19CD9;">[Enter]</span> to toggle active/idle, and <span style="color: #B19CD9;">[&#96;]</span> to change channels.

9. **View Saved Logs**
   - Inspect persistent records stored on LittleFS (<span style="color: #B19CD9;">/packet_log.txt</span>). Use <span style="color: #B19CD9;">[o]</span>/<span style="color: #B19CD9;">[k]</span> to navigate logs and <span style="color: #B19CD9;">[c]</span> to clear/delete entries.
