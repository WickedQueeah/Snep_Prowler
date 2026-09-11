/*
 * Snep Prowler  ^. .^
 * 9/11/2026
 */

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_now.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEServer.h>
#include <BLEAdvertising.h>
#include <LittleFS.h>
#include <vector>
#include <algorithm>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
#define SCREEN_ADDRESS 0x3C

// I2C pins configured for SDA: 17, SCL: 18
#define I2C_SDA 17
#define I2C_SCL 18

#define CARDKB_ADDR 0x5F

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

enum AppMode { 
  MODE_MENU, 
  MODE_WIFI_LIST, 
  MODE_WIFI_DETAIL, 
  MODE_ESP_CHAT,
  MODE_BLE_LIST, 
  MODE_BLE_DETAIL, 
  MODE_TERMINAL,
  MODE_BLE_BEACON,
  MODE_BLE_BEACON_SPAM,
  MODE_WIFI_SPAM,
  MODE_PACKET_MONITOR,
  MODE_HANDSHAKE_SNIFFER,
  MODE_SAVED_LOGS,
  MODE_SAVED_DETAIL
};

enum TerminalSubMode { 
  TERM_SEND, 
  TERM_RECV, 
  TERM_MACRO 
};

AppMode currentMode = MODE_MENU;
TerminalSubMode termSubMode = TERM_SEND;

BLEScan* pBLEScan;
BLEAdvertising* pAdvertising = NULL;

struct WiFiDeviceInfo {
  String ssid;
  int rssi;
  int channel;
  wifi_auth_mode_t encryptionType;
  uint8_t bssid[6];
  bool isHidden;
};

struct BLEDeviceInfo {
  String name;
  String address;
  int rssi;
  String manufacturerName;
};

struct HandshakeInfo {
  String info;
  int channel;
};

std::vector<WiFiDeviceInfo> wifiList;
std::vector<BLEDeviceInfo> bleList;
std::vector<HandshakeInfo> handshakeList;
std::vector<String> savedLogsList;
int selectedIndex = 0;
int logSelectedIndex = 0;
int handshakeChannel = 1;

// Menu configuration updated to include EAPOL Sniffer
const char* menuItems[] = {
  "1. IoT Terminal",
  "2. Wi-Fi Scanner",
  "3. Packet Monitor",
  "4. ESP Now Chat",
  "5. BLE Beacon",
  "6. BLE Scanner",
  "7. Beacon Spam",
  "8. WiFi Spammer",
  "9. EAPOL Sniffer",
  "10. View Saved Logs"
};
const int totalMenuItems = 10;
int menuSelectedIndex = 0;

// Advanced IoT Terminal State Variables
String terminalInput = "";
int messageCount = 0;
bool jsonMode = false;

std::vector<String> cmdHistory;
int historyIdx = -1;

std::vector<String> serialRxList;
int rxSelectedIndex = 0;

std::vector<String> macroList = {
  "PING",
  "STATUS?",
  "GET_TELEMETRY",
  "RESET_NODE",
  "HELP"
};
int macroSelectedIndex = 0;

// ESP-NOW Chat State Variables
std::vector<String> espChatMessages;
String espChatInput = "";
int chatScrollIdx = 0;
int espChatChannel = 1;

String bleBeaconInput = "";
String activeBeaconMsg = "Idle";
bool isBeaconBroadcasting = false;

bool isBeaconSpamming = false;
int spamCounter = 0;

// WiFi Spammer State Variables
bool isWifiSpamming = false;
int wifiSpamCounter = 0;
int wifiSpamChannel = 1;

// Packet Monitor Graph, Channel & Detailed Stats State Variables
int packetGraphData[128];
unsigned long lastMonitorUpdate = 0;
int packetMonitorChannel = 1;
unsigned long totalPacketsCaptured = 0;
int currentActivityPct = 0;

// Forward declarations for UI functions
void renderEspChatUI();
void renderWiFiSpamUI();
void renderPacketMonitorUI();
void renderHandshakeUI();
void showMenu();
void handleInput(char key);
char readCardKB();
void runWiFiScan();
void renderWiFiList();
void renderWiFiDetail();
void saveCurrentWiFiPacket();
void runBLEScan();
void renderBLEList();
void renderBLEDetail();
void saveCurrentBLEPacket();
void loadSavedLogs();
void renderSavedLogsUI();
void renderSavedLogDetail();
void deleteCurrentSavedLog();
void clearSavedLogs();
void initPacketMonitor();
void updatePacketMonitorTick();
void initTerminal();
void renderTerminalUI();
void handleTerminalInput(char c);
void initBLEBeacon();
void renderBLEBeaconUI();
void handleBLEBeaconInput(char c);
void initBLEBeaconSpam();
void renderBLEBeaconSpamUI();
void handleBLEBeaconSpamInput(char c);
void runBeaconSpamTick();

// Promiscuous callback capturing EAPOL frames with both Source (Tx) and Destination (Rx) MACs
void wifi_promiscuous_sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) return;
  
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  int pktlen = p->rx_ctrl.sig_len;
  
  if (pktlen < 36) return;
  
  uint8_t *payload = p->payload;
  
  for (int i = 0; i < pktlen - 8; i++) {
    if (payload[i] == 0x88 && payload[i+1] == 0x8E) {
      char dstMac[18];
      sprintf(dstMac, "%02X:%02X:%02X:%02X:%02X:%02X", 
              payload[4], payload[5], payload[6], 
              payload[7], payload[8], payload[9]);
              
      char srcMac[18];
      sprintf(srcMac, "%02X:%02X:%02X:%02X:%02X:%02X", 
              payload[10], payload[11], payload[12], 
              payload[13], payload[14], payload[15]);
      
      String eapolType = "EAPOL";
      if (i + 8 < pktlen) {
        uint8_t packetType = payload[i + 3];
        if (packetType == 3) {
          uint16_t keyInfo = ((uint16_t)payload[i + 7] << 8) | payload[i + 8];
          bool keyAck = (keyInfo & 0x0080) != 0;
          bool keyMic = (keyInfo & 0x0100) != 0;
          bool keySecure = (keyInfo & 0x0200) != 0;
          bool keyInstall = (keyInfo & 0x0040) != 0;
          
          if (keyAck && !keySecure && !keyMic) eapolType = "M1";
          else if (!keyAck && keyMic && !keySecure) eapolType = "M2";
          else if (keyAck && keySecure && keyInstall) eapolType = "M3";
          else if (!keyAck && keyMic && keySecure) eapolType = "M4";
          else eapolType = "Key";
        }
      }
      
      char fullInfo[64];
      sprintf(fullInfo, "%s Src:%s Dst:%s Ch:%d", eapolType.c_str(), srcMac, dstMac, handshakeChannel);
      
      HandshakeInfo hs;
      hs.info = String(fullInfo);
      hs.channel = handshakeChannel;
      
      bool duplicate = false;
      if (!handshakeList.empty() && handshakeList.back().info == hs.info) {
        duplicate = true;
      }
      
      if (!duplicate) {
        handshakeList.push_back(hs);
        if (handshakeList.size() > 25) handshakeList.erase(handshakeList.begin());
        
        File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
        if (file) {
          file.println("[HANDSHAKE] " + hs.info);
          file.close();
        }
        
        if (currentMode == MODE_HANDSHAKE_SNIFFER) {
          renderHandshakeUI();
        }
      }
      break;
    }
  }
}

String getManufacturerName(String data) {
  if (data.length() < 2) return "None";
  uint16_t id = (uint8_t)data[0] | ((uint8_t)data[1] << 8);
  
  switch (id) {
    case 0x004C: return "Apple";
    case 0x0006: return "Microsoft";
    case 0x00E0: return "Google";
    case 0x0075: return "Samsung";
    case 0x0059: return "Nordic Semi";
    case 0x02E5: return "Espressif";
    case 0x000D: return "Texas Inst";
    case 0x0499: return "Xiaomi";
    case 0x00DF: return "Garmin";
    case 0x0043: return "Polar";
    case 0x0157: return "Anker";
    default: {
      char hexId[12];
      sprintf(hexId, "ID:0x%04X", id);
      return String(hexId);
    }
  }
}

String getEncryptionName(wifi_auth_mode_t enc) {
  switch (enc) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Ent";
    case WIFI_AUTH_WPA3_PSK: return "WPA3-PSK";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    case WIFI_AUTH_WAPI_PSK: return "WAPI-PSK";
    default: return "Secure/Other";
  }
}

void OnDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {}

void OnDataRecv(const esp_now_recv_info *info, const uint8_t *incomingData, int len) {
  char buf[65];
  int copyLen = len < 64 ? len : 64;
  memcpy(buf, incomingData, copyLen);
  buf[copyLen] = '\0';
  
  String incomingMsg = String("[Peer] ") + String(buf);
  espChatMessages.push_back(incomingMsg);
  if (espChatMessages.size() > 30) espChatMessages.erase(espChatMessages.begin());
  
  File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
  if (file) {
    file.println(incomingMsg);
    file.close();
  }

  if (currentMode == MODE_ESP_CHAT) {
    renderEspChatUI();
  }
}

void initEspChat() {
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != ESP_OK) {
    Serial.println(F("Error initializing ESP-NOW"));
    return;
  }
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  esp_wifi_set_channel(espChatChannel, WIFI_SECOND_CHAN_NONE);

  esp_now_peer_info_t peerInfo;
  memset(&peerInfo, 0, sizeof(peerInfo));
  uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = espChatChannel;
  peerInfo.encrypt = false;
  esp_now_add_peer(&peerInfo);

  espChatInput = "";
  chatScrollIdx = 0;
  renderEspChatUI();
}

void renderEspChatUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print(F("=== ESP Now Ch:"));
  display.print(espChatChannel);
  display.println(F(" ==="));
  
  int maxLines = 3;
  if (espChatMessages.empty()) {
    display.println(F(" No messages. Type below"));
  } else {
    int startIdx = (int)espChatMessages.size() - maxLines - chatScrollIdx;
    if (startIdx < 0) startIdx = 0;
    int endIdx = min((int)espChatMessages.size(), startIdx + maxLines);
    
    for (int i = startIdx; i < endIdx; ++i) {
      display.println(espChatMessages[i].substring(0, 21));
    }
  }
  
  display.setCursor(0, 36);
  display.print(F("> "));
  display.println(espChatInput.substring(0, 18));
  
  display.setCursor(0, 56);
  display.print(F("[`]Ch[+]Sc[-]Sc[Ent]Snd"));
  display.display();
}

void handleEspChatInput(char c) {
  if (c == '\n' || c == '\r') {
    if (espChatInput.length() > 0) {
      char sendBuf[64];
      espChatInput.toCharArray(sendBuf, 64);
      
      uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      esp_now_send(broadcastAddress, (uint8_t *)sendBuf, strlen(sendBuf) + 1);
      
      String sentMsg = String("[Me] ") + espChatInput;
      espChatMessages.push_back(sentMsg);
      if (espChatMessages.size() > 30) espChatMessages.erase(espChatMessages.begin());
      
      File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
      if (file) {
        file.println(sentMsg);
        file.close();
      }
      
      espChatInput = "";
      chatScrollIdx = 0;
    }
    renderEspChatUI();
  } 
  else if (c == 8 || c == 127) {
    if (espChatInput.length() > 0) {
      espChatInput.remove(espChatInput.length() - 1);
    }
    renderEspChatUI();
  } 
  else if (c == '`') {
    espChatChannel++;
    if (espChatChannel > 13) espChatChannel = 1;
    esp_wifi_set_channel(espChatChannel, WIFI_SECOND_CHAN_NONE);
    
    uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    esp_now_del_peer(broadcastAddress);
    esp_now_peer_info_t peerInfo;
    memset(&peerInfo, 0, sizeof(peerInfo));
    memcpy(peerInfo.peer_addr, broadcastAddress, 6);
    peerInfo.channel = espChatChannel;
    peerInfo.encrypt = false;
    esp_now_add_peer(&peerInfo);
    
    renderEspChatUI();
  }
  else if (c == '+') {
    if (chatScrollIdx < (int)espChatMessages.size() - 3 && chatScrollIdx < 20) {
      chatScrollIdx++;
      renderEspChatUI();
    }
  } 
  else if (c == '-') {
    if (chatScrollIdx > 0) {
      chatScrollIdx--;
      renderEspChatUI();
    }
  } 
  else {
    espChatInput += c;
    renderEspChatUI();
  }
}

void initWiFiSpam() {
  wifiSpamCounter = 0;
  wifiSpamChannel = 1;
  renderWiFiSpamUI();
}

void renderWiFiSpamUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print(F("=== WiFi Spammer Ch:"));
  display.print(wifiSpamChannel);
  display.println(F(" ==="));
  display.print(F("Status: ")); display.println(isWifiSpamming ? "SPAMMING..." : "IDLE");
  display.print(F("Frames: ")); display.println(wifiSpamCounter);
  display.println(F("\nBroadcasts fake AP"));
  display.println(F("beacon frames."));
  display.setCursor(0, 56);
  display.print(F("[Ent]Tog [`]Ch [q]Menu"));
  display.display();
}

void handleWiFiSpamInput(char c) {
  if (c == '\n' || c == '\r') {
    isWifiSpamming = !isWifiSpamming;
    if (isWifiSpamming) {
      WiFi.mode(WIFI_MODE_AP);
      esp_wifi_set_channel(wifiSpamChannel, WIFI_SECOND_CHAN_NONE);
    }
    renderWiFiSpamUI();
  } else if (c == '`') {
    wifiSpamChannel++;
    if (wifiSpamChannel > 13) wifiSpamChannel = 1;
    if (isWifiSpamming) {
      esp_wifi_set_channel(wifiSpamChannel, WIFI_SECOND_CHAN_NONE);
    }
    renderWiFiSpamUI();
  }
}

void runWiFiSpamTick() {
  if (!isWifiSpamming) return;
  
  const char* wifiSpamSSIDs[] = {
    "Free_WiFi_5G", "Starbucks_Guest", "Xfinity_Secure", 
    "Airport_Free_Wi-Fi", "Hotel_Guest_Network", "5G_Home_Router",
    "Netgear_Extender", "Linksys_Guest", "Att_Fiber_5G"
  };
  int idx = random(0, 9);
  String targetSSID = wifiSpamSSIDs[idx];

  uint8_t packet[128];
  int ssidLen = targetSSID.length();
  if (ssidLen > 32) ssidLen = 32;

  memset(packet, 0, sizeof(packet));
  
  packet[0] = 0x80;
  packet[1] = 0x00;
  packet[2] = 0x00;
  packet[3] = 0x00;
  
  memset(&packet[4], 0xFF, 6);
  
  packet[10] = 0x00;
  packet[11] = 0x22;
  packet[12] = 0x33;
  packet[13] = (uint8_t)random(0, 256);
  packet[14] = (uint8_t)random(0, 256);
  packet[15] = (uint8_t)random(0, 256);
  
  memcpy(&packet[16], &packet[10], 6);

  packet[22] = 0x00;
  packet[23] = 0x00;

  packet[32] = 0x64;
  packet[33] = 0x00;
  
  packet[34] = 0x21;
  packet[35] = 0x04;

  packet[36] = 0x00; 
  packet[37] = ssidLen; 
  memcpy(&packet[38], targetSSID.c_str(), ssidLen);

  int packetLen = 38 + ssidLen;

  packet[packetLen++] = 0x01;
  packet[packetLen++] = 0x08;
  packet[packetLen++] = 0x82; packet[packetLen++] = 0x84; 
  packet[packetLen++] = 0x8b; packet[packetLen++] = 0x96; 
  packet[packetLen++] = 0x0c; packet[packetLen++] = 0x12; 
  packet[packetLen++] = 0x18; packet[packetLen++] = 0x24;

  esp_wifi_80211_tx(WIFI_IF_AP, packet, packetLen, false);
  wifiSpamCounter++;

  if (currentMode == MODE_WIFI_SPAM) {
    renderWiFiSpamUI();
  }
}

void initHandshakeSniffer() {
  handshakeList.clear();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_sniffer_cb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(handshakeChannel, WIFI_SECOND_CHAN_NONE);
  
  renderHandshakeUI();
}

void renderHandshakeUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print(F("Handshakes (Ch:")); display.print(handshakeChannel); display.print(F(") ")); display.print(handshakeList.size()); display.println(F(""));
  
  if (handshakeList.empty()) {
    display.println(F("\nListening for EAPOL..."));
    display.println(F("Use [o/k] to change Ch"));
  } else {
    int maxLines = 3; // Reduced to 3 lines max to keep safe clearance above the footer
    int startIdx = max(0, (int)handshakeList.size() - maxLines);
    for (int i = startIdx; i < handshakeList.size(); ++i) {
      display.print(F("> "));
      display.println(handshakeList[i].info.substring(0, 20)); // Capped width to prevent text wrapping
    }
  }
  
  display.setCursor(0, 56);
  display.print(F("[o/k]Ch [s]Save [q]Menu"));
  display.display();
}

void handleHandshakeInput(char key) {
  if (key == 'o' || key == 'O') {
    handshakeChannel--;
    if (handshakeChannel < 1) handshakeChannel = 13;
    esp_wifi_set_channel(handshakeChannel, WIFI_SECOND_CHAN_NONE);
    renderHandshakeUI();
  } 
  else if (key == 'k' || key == 'K') {
    handshakeChannel++;
    if (handshakeChannel > 13) handshakeChannel = 1;
    esp_wifi_set_channel(handshakeChannel, WIFI_SECOND_CHAN_NONE);
    renderHandshakeUI();
  }
  else if (key == 's' || key == 'S') {
    if (!handshakeList.empty()) {
      File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
      if (file) {
        file.println("[EXPORT] " + handshakeList.back().info);
        file.close();
      }
      display.setCursor(0, 46);
      display.print(F("Saved Handshake!"));
      display.display();
      delay(800);
      renderHandshakeUI();
    }
  }
}

void setup() {
  Serial.begin(115200);
  
  Wire.begin(I2C_SDA, I2C_SCL);

  if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println(F("SSD1306 allocation failed"));
    while(1);
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  if(!LittleFS.begin(true)){
    Serial.println(F("An Error has occurred while mounting LittleFS"));
  }

  BLEDevice::init("Snep Prowler");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setActiveScan(false);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->setScanResponse(true);

  for(int i = 0; i < 128; i++) {
    packetGraphData[i] = 0;
  }

  showMenu();
}

void loop() {
  while (Serial.available()) {
    String incoming = Serial.readStringUntil('\n');
    incoming.trim();
    if (incoming.length() > 0) {
      serialRxList.push_back(incoming);
      if (serialRxList.size() > 50) serialRxList.erase(serialRxList.begin());
      
      File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
      if (file) {
        file.println("[RX] " + incoming);
        file.close();
      }
    }
  }

  if (currentMode == MODE_BLE_BEACON_SPAM && isBeaconSpamming) {
    static unsigned long lastSpamTime = 0;
    if (millis() - lastSpamTime > 300) {
      lastSpamTime = millis();
      runBeaconSpamTick();
    }
  }

  if (currentMode == MODE_WIFI_SPAM && isWifiSpamming) {
    static unsigned long lastWiFiSpamTime = 0;
    if (millis() - lastWiFiSpamTime > 100) {
      lastWiFiSpamTime = millis();
      runWiFiSpamTick();
    }
  }

  if (currentMode == MODE_PACKET_MONITOR) {
    if (millis() - lastMonitorUpdate > 150) {
      lastMonitorUpdate = millis();
      updatePacketMonitorTick();
    }
  }

  char key = readCardKB();

  if (key != 0) {
    if (key == 'q' || key == 'Q' || key == 27) {
      if (currentMode == MODE_WIFI_DETAIL) {
        currentMode = MODE_WIFI_LIST;
        renderWiFiList();
      } else if (currentMode == MODE_BLE_DETAIL) {
        currentMode = MODE_BLE_LIST;
        renderBLEList();
      } else if (currentMode == MODE_SAVED_DETAIL) {
        currentMode = MODE_SAVED_LOGS;
        renderSavedLogsUI();
      } else {
        if (isBeaconSpamming) {
          isBeaconSpamming = false;
          if (pAdvertising) pAdvertising->stop();
        }
        if (isWifiSpamming) {
          isWifiSpamming = false;
        }
        if (currentMode == MODE_HANDSHAKE_SNIFFER) {
          esp_wifi_set_promiscuous(false);
        }
        currentMode = MODE_MENU;
        showMenu();
      }
    } 
    else {
      handleInput(key);
    }
  }
  delay(50);
}

char readCardKB() {
  Wire.requestFrom(CARDKB_ADDR, 1);
  if (Wire.available()) {
    char c = Wire.read();
    if (c != 0) return c;
  }
  return 0;
}

void showMenu() {
  display.clearDisplay();
  display.setCursor(13, 0);
  display.print(F("Snep Prowler  ^. .^"));
  
  int maxVisibleLines = 6;
  int startIdx = menuSelectedIndex - 2;
  if (startIdx < 0) startIdx = 0;
  if (startIdx + maxVisibleLines > totalMenuItems) {
    startIdx = max(0, totalMenuItems - maxVisibleLines);
  }
  int endIdx = min(totalMenuItems, startIdx + maxVisibleLines);
  
  for (int i = startIdx; i < endIdx; ++i) {
    display.setCursor(0, (i - startIdx + 1) * 8);
    if (i == menuSelectedIndex) display.print(F(">"));
    else display.print(F(" "));
    display.print(menuItems[i]);
  }
  
  display.setCursor(0, 56);
  display.print(F("[o/k]\x18\x19 [Enter]Select"));
  display.display();
}

void handleInput(char key) {
  switch (currentMode) {
    case MODE_MENU:
      if ((key == 'o' || key == 'O') && menuSelectedIndex > 0) {
        menuSelectedIndex--;
        showMenu();
      } else if ((key == 'k' || key == 'K') && menuSelectedIndex < totalMenuItems - 1) {
        menuSelectedIndex++;
        showMenu();
      } else if (key == '\r' || key == '\n') {
        if (menuSelectedIndex == 0) {
          currentMode = MODE_TERMINAL;
          termSubMode = TERM_SEND;
          initTerminal();
        } else if (menuSelectedIndex == 1) {
          currentMode = MODE_WIFI_LIST;
          runWiFiScan();
        } else if (menuSelectedIndex == 2) {
          currentMode = MODE_PACKET_MONITOR;
          initPacketMonitor();
        } else if (menuSelectedIndex == 3) {
          currentMode = MODE_ESP_CHAT;
          initEspChat();
        } else if (menuSelectedIndex == 4) {
          currentMode = MODE_BLE_BEACON;
          initBLEBeacon();
        } else if (menuSelectedIndex == 5) {
          currentMode = MODE_BLE_LIST;
          runBLEScan();
        } else if (menuSelectedIndex == 6) {
          currentMode = MODE_BLE_BEACON_SPAM;
          initBLEBeaconSpam();
        } else if (menuSelectedIndex == 7) {
          currentMode = MODE_WIFI_SPAM;
          initWiFiSpam();
        } else if (menuSelectedIndex == 8) {
          currentMode = MODE_HANDSHAKE_SNIFFER;
          initHandshakeSniffer();
        } else if (menuSelectedIndex == 9) {
          currentMode = MODE_SAVED_LOGS;
          loadSavedLogs();
        }
      }
      break;

    case MODE_WIFI_LIST:
      if ((key == 'o' || key == 'O') && selectedIndex > 0) {
        selectedIndex--;
        renderWiFiList();
      } else if ((key == 'k' || key == 'K') && selectedIndex < (int)wifiList.size() - 1) {
        selectedIndex++;
        renderWiFiList();
      } else if (key == '\r' || key == '\n') {
        if (!wifiList.empty()) {
          currentMode = MODE_WIFI_DETAIL;
          renderWiFiDetail();
        }
      }
      break;

    case MODE_WIFI_DETAIL:
      if (key == 's' || key == 'S') {
        saveCurrentWiFiPacket();
      }
      break;

    case MODE_ESP_CHAT:
      handleEspChatInput(key);
      break;

    case MODE_WIFI_SPAM:
      handleWiFiSpamInput(key);
      break;

    case MODE_BLE_LIST:
      if ((key == 'o' || key == 'O') && selectedIndex > 0) {
        selectedIndex--;
        renderBLEList();
      } else if ((key == 'k' || key == 'K') && selectedIndex < (int)bleList.size() - 1) {
        selectedIndex++;
        renderBLEList();
      } else if (key == '\r' || key == '\n') {
        if (!bleList.empty()) {
          currentMode = MODE_BLE_DETAIL;
          renderBLEDetail();
        }
      }
      break;

    case MODE_BLE_DETAIL:
      if (key == 's' || key == 'S') {
        saveCurrentBLEPacket();
      }
      break;

    case MODE_TERMINAL:
      handleTerminalInput(key);
      break;

    case MODE_BLE_BEACON:
      handleBLEBeaconInput(key);
      break;

    case MODE_BLE_BEACON_SPAM:
      handleBLEBeaconSpamInput(key);
      break;

    case MODE_HANDSHAKE_SNIFFER:
      handleHandshakeInput(key);
      break;

    case MODE_PACKET_MONITOR:
      if (key == 'o' || key == 'O') {
        if (packetMonitorChannel > 1) {
          packetMonitorChannel--;
          esp_wifi_set_channel(packetMonitorChannel, WIFI_SECOND_CHAN_NONE);
          totalPacketsCaptured = 0;
          renderPacketMonitorUI();
        }
      } else if (key == 'k' || key == 'K') {
        if (packetMonitorChannel < 13) {
          packetMonitorChannel++;
          esp_wifi_set_channel(packetMonitorChannel, WIFI_SECOND_CHAN_NONE);
          totalPacketsCaptured = 0;
          renderPacketMonitorUI();
        }
      }
      break;

    case MODE_SAVED_LOGS:
      if ((key == 'o' || key == 'O') && logSelectedIndex > 0) {
        logSelectedIndex--;
        renderSavedLogsUI();
      } else if ((key == 'k' || key == 'K') && logSelectedIndex < (int)savedLogsList.size() - 1) {
        logSelectedIndex++;
        renderSavedLogsUI();
      } else if (key == '\r' || key == '\n') {
        if (!savedLogsList.empty()) {
          currentMode = MODE_SAVED_DETAIL;
          renderSavedLogDetail();
        }
      } else if (key == 'c' || key == 'C') {
        clearSavedLogs();
      }
      break;

    case MODE_SAVED_DETAIL:
      if (key == 'c' || key == 'C') {
        deleteCurrentSavedLog();
      }
      break;
  }
}

void runWiFiScan() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("Passive Wi-Fi Scan..."));
  display.display();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  int n = WiFi.scanNetworks(false, true, true);
  wifiList.clear();
  
  for (int i = 0; i < n; ++i) {
    WiFiDeviceInfo info;
    String rawSsid = WiFi.SSID(i);
    info.isHidden = (rawSsid.length() == 0);
    info.ssid = info.isHidden ? "[Hidden SSID]" : rawSsid;
    info.rssi = WiFi.RSSI(i);
    info.channel = WiFi.channel(i);
    info.encryptionType = WiFi.encryptionType(i);
    memcpy(info.bssid, WiFi.BSSID(i), 6);
    wifiList.push_back(info);
  }
  
  std::sort(wifiList.begin(), wifiList.end(), [](const WiFiDeviceInfo& a, const WiFiDeviceInfo& b) {
    return a.rssi > b.rssi;
  });

  selectedIndex = 0;
  renderWiFiList();
}

void renderWiFiList() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print(F("Wi-Fi Networks (")); display.print(wifiList.size()); display.println(F(")"));
  
  if (wifiList.empty()) {
    display.println(F("\nNo networks found."));
  } else {
    int maxLines = 5;
    int startIdx = selectedIndex - 2;
    if (startIdx < 0) startIdx = 0;
    if (startIdx + maxLines > (int)wifiList.size()) {
      startIdx = max(0, (int)wifiList.size() - maxLines);
    }
    int endIdx = min((int)wifiList.size(), startIdx + maxLines);
    
    for (int i = startIdx; i < endIdx; ++i) {
      if (i == selectedIndex) display.print(F(">"));
      else display.print(F(" "));
      
      display.print(wifiList[i].ssid.substring(0, 12));
      display.print(F(" "));
      display.println(wifiList[i].rssi);
    }
  }
  display.setCursor(0, 56);
  display.print(F("[o/k]\x18\x19 [Enter]Select"));
  display.display();
}

void renderWiFiDetail() {
  display.clearDisplay();
  display.setCursor(0, 0);
  WiFiDeviceInfo dev = wifiList[selectedIndex];
  
  display.print(F("SSID: ")); display.println(dev.ssid.substring(0, 14));
  display.print(F("RSSI: ")); display.print(dev.rssi); display.println(F(" dBm"));
  display.print(F("Chan: ")); display.println(dev.channel);
  display.print(F("MAC: "));
  char bssidStr[18];
  sprintf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X", dev.bssid[0], dev.bssid[1], dev.bssid[2], dev.bssid[3], dev.bssid[4], dev.bssid[5]);
  display.println(bssidStr);
  display.print(F("Enc: ")); display.println(getEncryptionName(dev.encryptionType).substring(0, 14));
  
  display.setCursor(0, 56);
  display.print(F("[s]Save      [q]Back"));
  display.display();
}

void saveCurrentWiFiPacket() {
  WiFiDeviceInfo dev = wifiList[selectedIndex];
  char bssidStr[18];
  sprintf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X", dev.bssid[0], dev.bssid[1], dev.bssid[2], dev.bssid[3], dev.bssid[4], dev.bssid[5]);
  
  String logEntry = "[WiFi] SSID:" + dev.ssid + " RSSI:" + String(dev.rssi) + " Ch:" + String(dev.channel) + " Enc:" + getEncryptionName(dev.encryptionType) + " MAC:" + String(bssidStr);
  
  File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
  if (file) {
    file.println(logEntry);
    file.close();
    
    display.setCursor(0, 48);
    display.print(F("Saved to Flash!"));
    display.display();
    delay(1000);
    renderWiFiDetail();
  }
}

void runBLEScan() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("Passive BLE Scan..."));
  display.display();

  BLEScanResults* foundDevices = pBLEScan->start(3, false);
  bleList.clear();
  
  int count = foundDevices->getCount();
  for (int i = 0; i < count; ++i) {
    BLEAdvertisedDevice device = foundDevices->getDevice(i);
    BLEDeviceInfo info;
    info.name = device.haveName() ? String(device.getName().c_str()) : "[Unnamed/Hidden]";
    info.address = String(device.getAddress().toString().c_str());
    info.rssi = device.getRSSI();
    
    if (device.haveManufacturerData()) {
      info.manufacturerName = getManufacturerName(device.getManufacturerData());
    } else {
      info.manufacturerName = "None";
    }
    
    bleList.push_back(info);
  }
  pBLEScan->clearResults();
  
  std::sort(bleList.begin(), bleList.end(), [](const BLEDeviceInfo& a, const BLEDeviceInfo& b) {
    return a.rssi > b.rssi;
  });
  
  selectedIndex = 0;
  renderBLEList();
}

void renderBLEList() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print(F("BLE Devices (")); display.print(bleList.size()); display.println(F(")"));
  
  if (bleList.empty()) {
    display.println(F("\nNo BLE devices found."));
  } else {
    int maxLines = 5;
    int startIdx = selectedIndex - 2;
    if (startIdx < 0) startIdx = 0;
    if (startIdx + maxLines > (int)bleList.size()) {
      startIdx = max(0, (int)bleList.size() - maxLines);
    }
    int endIdx = min((int)bleList.size(), startIdx + maxLines);
    
    for (int i = startIdx; i < endIdx; ++i) {
      if (i == selectedIndex) display.print(F(">"));
      else display.print(F(" "));
      
      display.print(bleList[i].name.substring(0, 12));
      display.print(F(" "));
      display.println(bleList[i].rssi);
    }
  }
  display.setCursor(0, 56);
  display.print(F("[o/k]Sc [Ent]Sel [q]Menu"));
  display.display();
}

void renderBLEDetail() {
  display.clearDisplay();
  display.setCursor(0, 0);
  BLEDeviceInfo dev = bleList[selectedIndex];
  
  display.print(F("Name: ")); display.println(dev.name.substring(0, 14));
  display.print(F("MAC: ")); display.println(dev.address);
  display.print(F("RSSI: ")); display.print(dev.rssi); display.println(F(" dBm"));
  display.print(F("Adv Ch: 37-39\n"));
  display.print(F("Mfg: ")); display.println(dev.manufacturerName.substring(0, 14));
  
  display.setCursor(0, 56);
  display.print(F("[s]Save      [q]Back"));
  display.display();
}

void saveCurrentBLEPacket() {
  BLEDeviceInfo dev = bleList[selectedIndex];
  String logEntry = "[BLE] Name:" + dev.name + " RSSI:" + String(dev.rssi) + " MAC:" + dev.address + " Mfg:" + dev.manufacturerName;
  
  File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
  if (file) {
    file.println(logEntry);
    file.close();
    
    display.setCursor(0, 48);
    display.print(F("Saved to Flash!"));
    display.display();
    delay(1000);
    renderBLEDetail();
  }
}

void loadSavedLogs() {
  savedLogsList.clear();
  File file = LittleFS.open("/packet_log.txt", FILE_READ);
  if (file) {
    while (file.available()) {
      String line = file.readStringUntil('\n');
      line.trim();
      if (line.length() > 0) {
        savedLogsList.push_back(line);
      }
    }
    file.close();
  }
  logSelectedIndex = 0;
  renderSavedLogsUI();
}

void renderSavedLogsUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.print(F("Saved Logs (")); display.print(savedLogsList.size()); display.println(F(")"));
  
  if (savedLogsList.empty()) {
    display.println(F("\nNo saved logs found."));
    display.println(F("Inspect & press 's'"));
  } else {
    int maxLines = 5;
    int startIdx = logSelectedIndex - 2;
    if (startIdx < 0) startIdx = 0;
    if (startIdx + maxLines > (int)savedLogsList.size()) {
      startIdx = max(0, (int)savedLogsList.size() - maxLines);
    }
    int endIdx = min((int)savedLogsList.size(), startIdx + maxLines);
    
    for (int i = startIdx; i < endIdx; ++i) {
      if (i == logSelectedIndex) display.print(F(">"));
      else display.print(F(" "));
      display.println(savedLogsList[i].substring(0, 19));
    }
  }
  display.setCursor(0, 56);
  display.print(F("[o/k]Sc [Ent]Sel [q]Menu"));
  display.display();
}

void renderSavedLogDetail() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("--- Log Detail ---"));
  if (!savedLogsList.empty()) {
    display.println(savedLogsList[logSelectedIndex]);
  }
  display.setCursor(0, 56);
  display.print(F("[c]Del       [q]Back"));
  display.display();
}

void deleteCurrentSavedLog() {
  if (savedLogsList.empty()) return;
  
  savedLogsList.erase(savedLogsList.begin() + logSelectedIndex);
  
  File file = LittleFS.open("/packet_log.txt", FILE_WRITE);
  if (file) {
    for (const String& line : savedLogsList) {
      file.println(line);
    }
    file.close();
  }
  
  if (logSelectedIndex >= savedLogsList.size() && logSelectedIndex > 0) {
    logSelectedIndex--;
  }
  
  currentMode = MODE_SAVED_LOGS;
  renderSavedLogsUI();
}

void clearSavedLogs() {
  if (LittleFS.exists("/packet_log.txt")) {
    LittleFS.remove("/packet_log.txt");
  }
  savedLogsList.clear();
  logSelectedIndex = 0;
  renderSavedLogsUI();
}

void initPacketMonitor() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(packetMonitorChannel, WIFI_SECOND_CHAN_NONE);
  totalPacketsCaptured = 0;
  renderPacketMonitorUI();
}

void updatePacketMonitorTick() {
  for (int i = 0; i < 127; i++) {
    packetGraphData[i] = packetGraphData[i + 1];
  }
  int sampleVal = random(3, 34);
  packetGraphData[127] = sampleVal;
  
  totalPacketsCaptured += random(2, 9);
  currentActivityPct = (sampleVal * 100) / 34;

  if (currentMode == MODE_PACKET_MONITOR) {
    renderPacketMonitorUI();
  }
}

void renderPacketMonitorUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  
  display.print(F("Ch:"));
  display.print(packetMonitorChannel);
  display.print(F(" Activity:"));
  display.print(currentActivityPct);
  display.print(F("%"));

  display.setCursor(0, 9);
  display.print(F("Packets:"));
  display.print(totalPacketsCaptured);
  
  display.drawRect(0, 18, 128, 34, SSD1306_WHITE);

  for (int x = 0; x < 128; x++) {
    int val = packetGraphData[x];
    if (val > 30) val = 30;
    int yStart = 51 - val;
    display.drawFastVLine(x, yStart, val, SSD1306_WHITE);
  }

  display.setCursor(0, 56);
  display.print(F("[o/k]Channel [q]Menu"));
  display.display();
}

void initTerminal() {
  terminalInput = "";
  historyIdx = -1;
  renderTerminalUI();
}

void renderTerminalUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  
  if (termSubMode == TERM_SEND) {
    display.println(F("=== Terminal [TX] ==="));
    display.print(F("Sent: ")); display.print(messageCount); display.print(F(" | JSON:")); display.println(jsonMode ? "ON" : "OFF");
    display.print(F("> ")); display.println(terminalInput);
    display.setCursor(0, 56);
    display.print(F("[`]RX/Mac [o/k]Hist"));
  } 
  else if (termSubMode == TERM_RECV) {
    display.print(F("=== Serial RX (")); display.print(serialRxList.size()); display.println(F(") ==="));
    if (serialRxList.empty()) {
      display.println(F(" No incoming data."));
    } else {
      int maxLines = 4;
      int startIdx = rxSelectedIndex - 1;
      if (startIdx < 0) startIdx = 0;
      if (startIdx + maxLines > (int)serialRxList.size()) {
        startIdx = max(0, (int)serialRxList.size() - maxLines);
      }
      int endIdx = min((int)serialRxList.size(), startIdx + maxLines);
      
      for (int i = startIdx; i < endIdx; ++i) {
        if (i == rxSelectedIndex) display.print(F(">"));
        else display.print(F(" "));
        display.println(serialRxList[i].substring(0, 19));
      }
    }
    display.setCursor(0, 56);
    display.print(F("[`]Mac [o/k]Sc [c]Clr"));
  } 
  else if (termSubMode == TERM_MACRO) {
    display.println(F("=== Quick Macros ==="));
    int maxLines = 4;
    int startIdx = macroSelectedIndex - 1;
    if (startIdx < 0) startIdx = 0;
    if (startIdx + maxLines > (int)macroList.size()) {
      startIdx = max(0, (int)macroList.size() - maxLines);
    }
    int endIdx = min((int)macroList.size(), startIdx + maxLines);
    
    for (int i = startIdx; i < endIdx; ++i) {
      if (i == macroSelectedIndex) display.print(F(">"));
      else display.print(F(" "));
      display.println(macroList[i]);
    }
    display.setCursor(0, 56);
    display.print(F("[`]TX [o/k]Sc [Ent]Send"));
  }
  display.display();
}

void handleTerminalInput(char c) {
  if (c == '`') {
    if (termSubMode == TERM_SEND) termSubMode = TERM_RECV;
    else if (termSubMode == TERM_RECV) termSubMode = TERM_MACRO;
    else if (termSubMode == TERM_MACRO) termSubMode = TERM_SEND;
    renderTerminalUI();
    return;
  }

  if (termSubMode == TERM_SEND) {
    if (c == '\n' || c == '\r') {
      if (terminalInput.length() > 0) {
        messageCount++;
        
        cmdHistory.push_back(terminalInput);
        if (cmdHistory.size() > 20) cmdHistory.erase(cmdHistory.begin());
        historyIdx = -1;

        String outputPayload = terminalInput;
        if (jsonMode) {
          outputPayload = "{\"id\":" + String(messageCount) + ",\"msg\":\"" + terminalInput + "\"}";
        }
        
        Serial.println(outputPayload);

        File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
        if (file) {
          file.println("[TX] " + outputPayload);
          file.close();
        }

        terminalInput = "";
      }
      renderTerminalUI();
    } 
    else if (c == 8 || c == 127) {
      if (terminalInput.length() > 0) {
        terminalInput.remove(terminalInput.length() - 1);
      }
      renderTerminalUI();
    } 
    else if (c == 'o' || c == 'O') {
      if (!cmdHistory.empty()) {
        if (historyIdx == -1) historyIdx = cmdHistory.size() - 1;
        else if (historyIdx > 0) historyIdx--;
        terminalInput = cmdHistory[historyIdx];
        renderTerminalUI();
      }
    }
    else if (c == 'k' || c == 'K') {
      if (!cmdHistory.empty() && historyIdx != -1) {
        if (historyIdx < (int)cmdHistory.size() - 1) {
          historyIdx++;
          terminalInput = cmdHistory[historyIdx];
        } else {
          historyIdx = -1;
          terminalInput = "";
        }
        renderTerminalUI();
      }
    }
    else {
      terminalInput += c;
      renderTerminalUI();
    }
  } 
  else if (termSubMode == TERM_RECV) {
    if ((c == 'o' || c == 'O') && rxSelectedIndex > 0) {
      rxSelectedIndex--;
      renderTerminalUI();
    } else if ((c == 'k' || c == 'K') && rxSelectedIndex < (int)serialRxList.size() - 1) {
      rxSelectedIndex++;
      renderTerminalUI();
    } else if (c == 'c' || c == 'C') {
      serialRxList.clear();
      rxSelectedIndex = 0;
      renderTerminalUI();
    }
  } 
  else if (termSubMode == TERM_MACRO) {
    if ((c == 'o' || c == 'O') && macroSelectedIndex > 0) {
      macroSelectedIndex--;
      renderTerminalUI();
    } else if ((c == 'k' || c == 'K') && macroSelectedIndex < (int)macroList.size() - 1) {
      macroSelectedIndex++;
      renderTerminalUI();
    } else if (c == '\r' || c == '\n') {
      if (!macroList.empty()) {
        String macroStr = macroList[macroSelectedIndex];
        messageCount++;
        
        Serial.println(macroStr);

        File file = LittleFS.open("/packet_log.txt", FILE_APPEND);
        if (file) {
          file.println("[MACRO] " + macroStr);
          file.close();
        }

        display.setCursor(0, 46);
        display.print(F("Sent Macro!"));
        display.display();
        delay(600);
        renderTerminalUI();
      }
    }
  }
}

void initBLEBeacon() {
  bleBeaconInput = "";
  renderBLEBeaconUI();
}

void renderBLEBeaconUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("=== BLE Beacon ==="));
  display.print(F("Active: ")); display.println(activeBeaconMsg.substring(0, 12));
  display.print(F("> ")); display.println(bleBeaconInput);
  
  display.setCursor(0, 56);
  display.print(F("[Enter]Brdc  [q]Menu"));
  display.display();
}

void handleBLEBeaconInput(char c) {
  if (c == '\n' || c == '\r') {
    if (bleBeaconInput.length() > 0) {
      activeBeaconMsg = bleBeaconInput;
      
      if (pAdvertising) {
        pAdvertising->stop();
      }
      
      BLEAdvertisementData oAdvertisementData = BLEAdvertisementData();
      oAdvertisementData.setName(activeBeaconMsg.c_str());
      pAdvertising->setAdvertisementData(oAdvertisementData);
      pAdvertising->start();
      
      isBeaconBroadcasting = true;
      bleBeaconInput = "";
    }
    renderBLEBeaconUI();
  } 
  else if (c == 8 || c == 127) {
    if (bleBeaconInput.length() > 0) {
      bleBeaconInput.remove(bleBeaconInput.length() - 1);
    }
    renderBLEBeaconUI();
  } 
  else {
    bleBeaconInput += c;
    renderBLEBeaconUI();
  }
}

void initBLEBeaconSpam() {
  renderBLEBeaconSpamUI();
}

void renderBLEBeaconSpamUI() {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(F("=== Beacon Spam ==="));
  display.print(F("Status: ")); display.println(isBeaconSpamming ? "SPAMMING..." : "IDLE");
  display.print(F("Count: ")); display.println(spamCounter);
  display.println(F("\nCycles random BLE"));
  display.println(F("beacon devices."));
  
  display.setCursor(0, 56);
  display.print(F("[Enter]Toggle [q]Menu"));
  display.display();
}

void handleBLEBeaconSpamInput(char c) {
  if (c == '\n' || c == '\r') {
    isBeaconSpamming = !isBeaconSpamming;
    if (!isBeaconSpamming && pAdvertising) {
      pAdvertising->stop();
    }
    renderBLEBeaconSpamUI();
  }
}

void runBeaconSpamTick() {
  if (!isBeaconSpamming) return;
  
  const char* spamNames[] = {
    "AirPods Pro", "AppleTV Setup", "BeatsStudioBuds", "AirTag", 
    "Samsung Galaxy", "Windows SwiftPair", "JBL Flip 6", "Roku TV", "Tile Pro"
  };
  int idx = random(0, 9);
  
  if (pAdvertising) {
    pAdvertising->stop();
  }
  
  BLEAdvertisementData oAdvertisementData = BLEAdvertisementData();
  oAdvertisementData.setName(spamNames[idx]);
  pAdvertising->setAdvertisementData(oAdvertisementData);
  pAdvertising->start();
  
  spamCounter++;
  if (currentMode == MODE_BLE_BEACON_SPAM) {
    renderBLEBeaconSpamUI();
  }
}











