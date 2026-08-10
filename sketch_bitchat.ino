#include <bluefruit.h>

#define MAX_FRAGMENTS      16
#define MAX_FRAGMENT_DATA  480
#define MAX_REASSEMBLED    8192

struct FragmentAssembly
{
  bool active;

  uint8_t id[8];

  uint16_t total;

  bool received[MAX_FRAGMENTS];

  uint16_t lengths[MAX_FRAGMENTS];

  uint8_t parts[MAX_FRAGMENTS][MAX_FRAGMENT_DATA];

  uint32_t startedAt;
};

FragmentAssembly fragmentAssembly;

// Bitchat Service UUID
BLEClientService bitchatService(
  BLEUuid("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C")
);

// 現段階では前に確認していたCharacteristic UUIDを使用
BLEClientCharacteristic bitchatChar(
  BLEUuid("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D")
);

static const uint8_t bitchatUuidLE[] = {
  0x5C, 0x4B, 0x3A, 0x2C,
  0x1D, 0x8E,
  0x3F, 0x9B,
  0x5A, 0x4C,
  0x9E, 0x4A,
  0x2D, 0x5E, 0x7B, 0xF4
};

bool connecting = false;

uint16_t readBE16(const uint8_t* p)
{
  return ((uint16_t)p[0] << 8) | p[1];
}

void printHex(const uint8_t* data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    if (data[i] < 0x10) {
      Serial.print('0');
    }

    Serial.print(data[i], HEX);

    if (i + 1 < len) {
      Serial.print('-');
    }
  }
}

void parse_bitchat_packet(uint8_t* data, uint16_t len)
{
  // v1 minimum = header 14 + senderID 8
  if (len < 22)
  {
    Serial.println("Packet too short");
    return;
  }

  uint8_t version = data[0];
  uint8_t type    = data[1];
  uint8_t ttl     = data[2];
  uint8_t flags   = data[11];

  if (version != 1)
  {
    Serial.print("Unsupported version: ");
    Serial.println(version);
    return;
  }

  uint16_t payloadLength = readBE16(data + 12);

  Serial.println();
  Serial.println("=== BITCHAT PACKET ===");

  Serial.print("Version: ");
  Serial.println(version);

  Serial.print("Type: 0x");
  if (type < 0x10) Serial.print('0');
  Serial.println(type, HEX);

  Serial.print("TTL: ");
  Serial.println(ttl);

  Serial.print("Flags: 0x");
  if (flags < 0x10) Serial.print('0');
  Serial.println(flags, HEX);

  Serial.print("Payload length: ");
  Serial.println(payloadLength);

  Serial.print("Sender ID: ");
  printHex(data + 14, 8);
  Serial.println();

  // 今はrecipient無しのpacketを対象
  size_t payloadOffset = 22;

  if (flags & 0x01)
  {
    // recipient IDあり
    payloadOffset += 8;
  }

  if (payloadOffset + payloadLength > len)
  {
    Serial.println("Incomplete packet");
    return;
  }

  // Fragment
  if (type == 0x20)
  {
    if (payloadLength < 12)
    {
      Serial.println("Invalid fragment");
      return;
    }

    const uint8_t* payload =
      data + payloadOffset;

    Serial.println("--- FRAGMENT ---");

    Serial.print("Fragment ID: ");
    printHex(payload, 8);
    Serial.println();

    uint16_t index =
      readBE16(payload + 8);

    uint16_t total =
      readBE16(payload + 10);

    Serial.print("Index: ");
    Serial.print(index);
    Serial.print(" / ");
    Serial.println(total);

    Serial.print("Fragment data length: ");
    Serial.println(payloadLength - 12);

    // 実際にassemblyへ投入
    handle_fragment(
      payload,
      payloadLength
    );

    return;
  }
}

void resetFragmentAssembly()
{
  memset(&fragmentAssembly, 0, sizeof(fragmentAssembly));
}

void handle_fragment(
  const uint8_t* payload,
  uint16_t payloadLength
)
{
  // fragment header:
  //
  // 8 bytes fragment ID
  // 2 bytes index
  // 2 bytes total

  if (payloadLength < 12)
  {
    Serial.println("Invalid fragment payload");
    return;
  }

  const uint8_t* fragmentId = payload;

  uint16_t index =
    ((uint16_t)payload[8] << 8) |
    payload[9];

  uint16_t total =
    ((uint16_t)payload[10] << 8) |
    payload[11];

  const uint8_t* fragmentData = payload + 12;

  uint16_t fragmentDataLength =
    payloadLength - 12;

  Serial.print("Fragment received: ");
  Serial.print(index);
  Serial.print(" / ");
  Serial.println(total);

  // とりあえず開発用上限
  if (total == 0 || total > MAX_FRAGMENTS)
  {
    Serial.println("Too many fragments");
    return;
  }

  if (index >= total)
  {
    Serial.println("Invalid fragment index");
    return;
  }

  if (fragmentDataLength > MAX_FRAGMENT_DATA)
  {
    Serial.println("Fragment too large");
    return;
  }

  // 30秒以上経過したassemblyは捨てる
  if (
    fragmentAssembly.active &&
    millis() - fragmentAssembly.startedAt > 30000
  )
  {
    Serial.println("Fragment assembly timeout");
    resetFragmentAssembly();
  }

  bool sameId =
    fragmentAssembly.active &&
    memcmp(
      fragmentAssembly.id,
      fragmentId,
      8
    ) == 0;

  // 新しいfragment ID
  if (!sameId)
  {
    resetFragmentAssembly();

    fragmentAssembly.active = true;

    memcpy(
      fragmentAssembly.id,
      fragmentId,
      8
    );

    fragmentAssembly.total = total;
    fragmentAssembly.startedAt = millis();

    Serial.print("New assembly: ");
    printHex(fragmentId, 8);
    Serial.println();
  }

  if (fragmentAssembly.total != total)
  {
    Serial.println("Fragment total mismatch");
    resetFragmentAssembly();
    return;
  }

  // 重複fragment
  if (fragmentAssembly.received[index])
  {
    Serial.println("Duplicate fragment ignored");
    return;
  }

  memcpy(
    fragmentAssembly.parts[index],
    fragmentData,
    fragmentDataLength
  );

  fragmentAssembly.lengths[index] =
    fragmentDataLength;

  fragmentAssembly.received[index] = true;

  // 何個揃ったか確認
  uint16_t receivedCount = 0;

  for (uint16_t i = 0; i < total; i++)
  {
    if (fragmentAssembly.received[i])
    {
      receivedCount++;
    }
  }

  Serial.print("Assembly progress: ");
  Serial.print(receivedCount);
  Serial.print(" / ");
  Serial.println(total);

  if (receivedCount != total)
  {
    return;
  }

  //
  // 全fragmentが揃った
  //

  static uint8_t reassembled[MAX_REASSEMBLED];

  uint16_t reassembledLength = 0;

  for (uint16_t i = 0; i < total; i++)
  {
    uint16_t partLength =
      fragmentAssembly.lengths[i];

    if (
      reassembledLength + partLength >
      MAX_REASSEMBLED
    )
    {
      Serial.println("Reassembled packet too large");
      resetFragmentAssembly();
      return;
    }

    memcpy(
      reassembled + reassembledLength,
      fragmentAssembly.parts[i],
      partLength
    );

    reassembledLength += partLength;
  }

  Serial.println();
  Serial.println("============================");
  Serial.println("FRAGMENT REASSEMBLY COMPLETE");
  Serial.println("============================");

  Serial.print("Length: ");
  Serial.println(reassembledLength);

  Serial.print("HEX: ");
  printHex(reassembled, reassembledLength);
  Serial.println();

  // 再帰処理前にassemblyを解放
  resetFragmentAssembly();

  // 復元された元Bitchat packetを解析
  parse_bitchat_packet(
    reassembled,
    reassembledLength
  );
}

void setup()
{
  Serial.begin(115200);

  while (!Serial) {
    delay(10);
  }

  Serial.println("Bitchat BLE scanner");

  Bluefruit.configCentralBandwidth(BANDWIDTH_MAX);
  Bluefruit.configPrphBandwidth(BANDWIDTH_MAX);

  // Central 1接続
  Bluefruit.begin(0, 1);

  Bluefruit.setName("XIAO-Bitchat");

  // Client Service / Characteristic登録
  bitchatService.begin();

  bitchatChar.setNotifyCallback(notify_callback);
  bitchatChar.begin();

  // Central callbacks
  Bluefruit.Central.setConnectCallback(connect_callback);
  Bluefruit.Central.setDisconnectCallback(disconnect_callback);

  // Scanner
  Bluefruit.Scanner.setRxCallback(scan_callback);
  Bluefruit.Scanner.restartOnDisconnect(true);

  Bluefruit.Scanner.setInterval(160, 80);
  Bluefruit.Scanner.useActiveScan(false);

  Serial.println("Scanning for Bitchat...");

  Bluefruit.Scanner.start(0);
}


void loop()
{
}


// --------------------------------------------------
// BLE scan
// --------------------------------------------------

void scan_callback(ble_gap_evt_adv_report_t* report)
{
  if (connecting) {
    Bluefruit.Scanner.resume();
    return;
  }

  const uint8_t* data = report->data.p_data;
  uint16_t len = report->data.len;

  bool isBitchat = false;

  for (uint16_t i = 0;
       i + sizeof(bitchatUuidLE) <= len;
       i++)
  {
    if (memcmp(
          data + i,
          bitchatUuidLE,
          sizeof(bitchatUuidLE)
        ) == 0)
    {
      isBitchat = true;
      break;
    }
  }

  if (!isBitchat) {
    Bluefruit.Scanner.resume();
    return;
  }

  Serial.println();
  Serial.println("=== BITCHAT FOUND ===");

  Serial.print("Address: ");
  Serial.printBufferReverse(
    report->peer_addr.addr,
    6,
    ':'
  );

  Serial.println();

  Serial.print("RSSI: ");
  Serial.println(report->rssi);

  Serial.println("Connecting...");

  connecting = true;

  // このreportの端末へ接続
  if (!Bluefruit.Central.connect(report))
  {
    Serial.println("connect() failed");

    connecting = false;
    Bluefruit.Scanner.resume();
  }
}


// --------------------------------------------------
// Connected
// --------------------------------------------------

void connect_callback(uint16_t conn_handle)
{
  Serial.println();
  Serial.println("=== CONNECTED ===");

  BLEConnection* connection = Bluefruit.Connection(conn_handle);

  if (connection)
  {
    Serial.print("Current MTU: ");
    Serial.println(connection->getMtu());
  }

  Serial.print("Connection handle: ");
  Serial.println(conn_handle);

  Serial.print("Discovering Bitchat service... ");

  if (!bitchatService.discover(conn_handle))
  {
    Serial.println("NOT FOUND");
    Bluefruit.disconnect(conn_handle);
    return;
  }

  Serial.println("FOUND");

  Serial.print("Discovering characteristic... ");

  if (!bitchatChar.discover())
  {
    Serial.println("NOT FOUND");
    Bluefruit.disconnect(conn_handle);
    return;
  }

  Serial.println("FOUND");

  Serial.print("Enabling notifications... ");

  if (!bitchatChar.enableNotify())
  {
    Serial.println("FAILED");
    return;
  }

  Serial.println("OK");

  // GATT discoveryが完全に終わったあと
  delay(200);

  if (connection)
  {
    Serial.print("MTU before exchange: ");
    Serial.println(connection->getMtu());

    Serial.print("Requesting MTU 247... ");

    if (connection->requestMtuExchange(247))
    {
      Serial.println("OK");
    }
    else
    {
      Serial.println("FAILED");
    }
  }

  delay(500);

  if (connection)
  {
    Serial.print("MTU after exchange: ");
    Serial.println(connection->getMtu());
  }

  Serial.println("Waiting for Bitchat packets...");
}


// --------------------------------------------------
// Notifications
// --------------------------------------------------

void notify_callback(
  BLEClientCharacteristic* chr,
  uint8_t* data,
  uint16_t len
)
{
  (void)chr;

  Serial.println();

  Serial.print("RX chunk [");
  Serial.print(len);
  Serial.println(" bytes]");

  Serial.print("HEX: ");
  printHex(data, len);
  Serial.println();

  parse_bitchat_packet(data, len);
}

// --------------------------------------------------
// Disconnected
// --------------------------------------------------

void disconnect_callback(
  uint16_t conn_handle,
  uint8_t reason
)
{
  (void) conn_handle;

  Serial.println();
  Serial.println("=== DISCONNECTED ===");

  Serial.print("Reason: 0x");
  Serial.println(reason, HEX);

  connecting = false;

  Serial.println("Scanning again...");
}