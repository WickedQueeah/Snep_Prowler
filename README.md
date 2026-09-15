# Snep Prowler ^. .^ Build & Operation

## 1. Hardware Specifications & Components

- **Microcontroller**: ESP32 S3 Development Board (ESP32-WROOM / Generic Node)
- **Display**: 0.96-inch SSD1306 or 2.43-inch SSD1309 I2C OLED Display (128x64 resolution, Address: `0x3C`)
- **Input Device**: M5Stack CardKB V2 Unit (I2C interface, Address: `0x5F`)
- **Storage**: Internal Flash partitioned with LittleFS file system for persistent logging (`/packet_log.txt`, `/notepad.txt`)

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
  - `LittleFS.h` (Flash file management for persistent logging and notes)
  - `<vector>`, `<algorithm>` (Standard Template Library containers)

## 4. Global Navigation & General Controls

- **Main Menu**: Use `[o]` (Up) and `[k]` (Down) to highlight options. Press `[Enter]` to select.
- **Exit / Return**: Press `[q]`, `[Q]`, or `[ESC]` from any active mode or detail screen to stop transmissions, save edits where applicable, and return to the previous view or main menu.

## 5. Function & Module Operation Instructions

1. **IoT Terminal**
   - Type commands using the CardKB V2 and press `[Enter]` to transmit over Serial (115200 baud).
   - Press `` ` `` (backtick) to switch sub-modes between TX, RX history inspection, and quick macros.
   - Use `[o]`/`[k]` to scroll through command history or incoming serial responses. Press `[c]` to clear RX logs.

2. **ESPNow Chat**
   - Decentralized peer-to-peer radio messaging. Type text and press `[Enter]` to broadcast to peers on the active channel.
   - Press `` ` `` to cycle communication channels (1-13).
   - Use `[+]` and `[-]` keys to scroll up and down through message history without occupying typing characters `[o]` and `[k]`.

3. **Tiny Notepad**
   - Provides a quick text scratchpad utility directly on the device using the CardKB V2 input layout.
   - Type text freely to draft notes, target reminders, or capture quick thoughts in the field.
   - Press `[Enter]` to save the new entry persistently to LittleFS (`/notepad.txt`), or press `[c]` to clear the current buffer.

4. **View Scan Logs**
   - Inspect persistent records stored on LittleFS (`/packet_log.txt`). Use `[o]`/`[k]` to navigate logs and `[c]` to clear/delete entries.

5. **Packet Monitor**
   - Displays a real-time scrolling histogram graph showing activity percentage and packet counters.
   - Use `[o]`/`[k]` to change channels (1-13). Changing channels resets the packet counter.

6. **WiFi Scanner**
   - Automatically scans surrounding access points. Use `[o]`/`[k]` to scroll through the list.
   - Press `[Enter]` on a network to view parameter details (RSSI, channel, BSSID MAC, encryption).
   - Press `[s]` to append the network log to internal flash storage.

7. **EAPOL Sniffer**
   - Listens in promiscuous mode to intercept WPA/WPA2 4-way handshake frames (M1, M2, M3, M4).
   - Displays the handshake stage, source MAC, destination MAC, and channel on screen while automatically recording events to LittleFS (`/packet_log.txt`).
   - Use `[o]`/`[k]` to change channels (1-13). Press `[s]` to save/export the latest entry to flash storage, or `[q]` to return to the menu and disable promiscuous mode.

8. **WiFi Spammer**
   - Broadcasts fake AP beacon frames mimicking popular public networks. Press `[Enter]` to toggle active/idle, and `` ` `` to change channels.

9. **BLE Beacon**
   - Type a custom string on the keyboard and press `[Enter]` to spin up a BLE advertisement beacon broadcasting that exact name.

10. **BLE Scanner**
    - Scans surrounding BLE peripherals. Use `[o]`/`[k]` to navigate and `[Enter]` to view details (MAC, RSSI, manufacturer ID). Press `[s]` to save to flash.

11. **BLE spammer**
    - Cycles multi-vendor BLE beacon profiles (AirTags, smart devices, audio gear). Press `[Enter]` to toggle active/idle.


