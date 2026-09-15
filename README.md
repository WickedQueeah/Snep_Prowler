# Snep Prowler ^. .^ Build Sheet & Operation Guide

## 1. Hardware Specifications & Components

- **Microcontroller**: ESP32 Development Board (ESP32-WROOM / Generic Node)[span_0](start_span)[span_0](end_span)
- **Display**: 0.96-inch SSD1306 I2C OLED Display (128x64 resolution, Address: `0x3C`)[span_1](start_span)[span_1](end_span)
- **Input Device**: M5Stack CardKB V2 Unit (I2C interface, Address: `0x5F`)[span_2](start_span)[span_2](end_span)
- **Storage**: Internal Flash partitioned with LittleFS file system for persistent logging (`/packet_log.txt`, `/notepad.txt`)[span_3](start_span)[span_3](end_span)

## 2. Pinout & Wiring Mapping

| Component | ESP32 Pin | Connection Details |
| :--- | :--- | :--- |
| **I2C SDA** | GPIO 17 | Shared line connected to OLED SDA and CardKB V2 SDA[span_4](start_span)[span_4](end_span) |
| **I2C SCL** | GPIO 18 | Shared line connected to OLED SCL and CardKB V2 SCL[span_5](start_span)[span_5](end_span) |
| **Power (VCC)** | 3.3V / 5V | Regulated power rail matching module specifications |
| **Ground (GND)** | GND | Common system ground |

## 3. Software Dependencies & Libraries

- **Core Architecture**: ESP32 Arduino Core v3.x / IDF v5.x
- **Display & UI Libraries**:
  - `Wire` (Built-in I2C communication)[span_6](start_span)[span_6](end_span)
  - `Adafruit_GFX` (Core graphics library)[span_7](start_span)[span_7](end_span)
  - `Adafruit_SSD1306` (OLED display controller)[span_8](start_span)[span_8](end_span)
- **Wireless & Networking**:
  - `WiFi.h` & `esp_wifi.h` (Wi-Fi operational modes, channel hopping, AP frame injection)[span_9](start_span)[span_9](end_span)
  - `esp_now.h` (Serverless peer-to-peer radio messaging protocol)[span_10](start_span)[span_10](end_span)
  - `BLEDevice.h`, `BLEScan.h`, `BLEAdvertising.h` (Bluetooth Low Energy management)[span_11](start_span)[span_11](end_span)
- **System Utilities**:
  - `LittleFS.h` (Flash file management for persistent logging and notes)[span_12](start_span)[span_12](end_span)
  - `<vector>`, `<algorithm>` (Standard Template Library containers)[span_13](start_span)[span_13](end_span)

## 4. Global Navigation & General Controls

- **Main Menu**: Use `[o]` (Up) and `[k]` (Down) to highlight options. Press `[Enter]` to select[span_14](start_span)[span_14](end_span).
- **Exit / Return**: Press `[q]`, `[Q]`, or `[ESC]` from any active mode or detail screen to stop transmissions, save edits where applicable, and return to the previous view or main menu[span_15](start_span)[span_15](end_span).

## 5. Function & Module Operation Instructions

1. **IoT Terminal**
   - Type commands using the CardKB V2 and press `[Enter]` to transmit over Serial (115200 baud)[span_16](start_span)[span_16](end_span).
   - Press `` ` `` (backtick) to switch sub-modes between TX, RX history inspection, and quick macros[span_17](start_span)[span_17](end_span).
   - Use `[o]`/`[k]` to scroll through command history or incoming serial responses[span_18](start_span)[span_18](end_span). Press `[c]` to clear RX logs[span_19](start_span)[span_19](end_span).

2. **ESPNow Chat**
   - Decentralized peer-to-peer radio messaging[span_20](start_span)[span_20](end_span). Type text and press `[Enter]` to broadcast to peers on the active channel[span_21](start_span)[span_21](end_span).
   - Press `` ` `` to cycle communication channels (1-13)[span_22](start_span)[span_22](end_span).
   - Use `[+]` and `[-]` keys to scroll up and down through message history without occupying typing characters `[o]` and `[k]`[span_23](start_span)[span_23](end_span).

3. **Tiny Notepad**
   - Provides a quick text scratchpad utility directly on the device using the CardKB V2 input layout[span_24](start_span)[span_24](end_span).
   - Type text freely to draft notes, target reminders, or capture quick thoughts in the field[span_25](start_span)[span_25](end_span).
   - Press `[Enter]` to save the new entry persistently to LittleFS (`/notepad.txt`), or press `[c]` to clear the current buffer[span_26](start_span)[span_26](end_span).

4. **View Scan Logs**
   - Inspect persistent records stored on LittleFS (`/packet_log.txt`)[span_27](start_span)[span_27](end_span). Use `[o]`/`[k]` to navigate logs and `[c]` to clear/delete entries[span_28](start_span)[span_28](end_span).

5. **Packet Monitor**
   - Displays a real-time scrolling histogram graph showing activity percentage and packet counters[span_29](start_span)[span_29](end_span).
   - Use `[o]`/`[k]` to change channels (1-13)[span_30](start_span)[span_30](end_span). Changing channels resets the packet counter[span_31](start_span)[span_31](end_span).

6. **WiFi Scanner**
   - Automatically scans surrounding access points[span_32](start_span)[span_32](end_span). Use `[o]`/`[k]` to scroll through the list[span_33](start_span)[span_33](end_span).
   - Press `[Enter]` on a network to view parameter details (RSSI, channel, BSSID MAC, encryption)[span_34](start_span)[span_34](end_span).
   - Press `[s]` to append the network log to internal flash storage[span_35](start_span)[span_35](end_span).

7. **EAPOL Sniffer**
   - Listens in promiscuous mode to intercept WPA/WPA2 4-way handshake frames (M1, M2, M3, M4)[span_36](start_span)[span_36](end_span).
   - Displays the handshake stage, source MAC, destination MAC, and channel on screen while automatically recording events to LittleFS (`/packet_log.txt`)[span_37](start_span)[span_37](end_span).
   - Use `[o]`/`[k]` to change channels (1-13). Press `[s]` to save/export the latest entry to flash storage, or `[q]` to return to the menu and disable promiscuous mode[span_38](start_span)[span_38](end_span).

8. **WiFi Spammer**
   - Broadcasts fake AP beacon frames mimicking popular public networks[span_39](start_span)[span_39](end_span). Press `[Enter]` to toggle active/idle, and `` ` `` to change channels[span_40](start_span)[span_40](end_span).

9. **BLE Beacon**
   - Type a custom string on the keyboard and press `[Enter]` to spin up a BLE advertisement beacon broadcasting that exact name[span_41](start_span)[span_41](end_span).

10. **BLE Scanner**
    - Scans surrounding BLE peripherals[span_42](start_span)[span_42](end_span). Use `[o]`/`[k]` to navigate and `[Enter]` to view details (MAC, RSSI, manufacturer ID)[span_43](start_span)[span_43](end_span). Press `[s]` to save to flash[span_44](start_span)[span_44](end_span).

11. **BLE spammer**
    - Cycles multi-vendor BLE beacon profiles (AirTags, smart devices, audio gear)[span_45](start_span)[span_45](end_span). Press `[Enter]` to toggle active/idle[span_46](start_span)[span_46](end_span).


