#include <bluefruit.h>
#include <Adafruit_nRFCrypto.h>
#include <nrf_cc310/include/crys_ec_edw_api.h>

#define MAX_FRAGMENTS      16
#define MAX_FRAGMENT_DATA  480
#define MAX_REASSEMBLED    8192
#define MAX_SIGNING_DATA   2048

struct FragmentAssembly
{
  bool active;

  uint8_t id[8];
  uint8_t originalType;

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

// Characteristic UUID confirmed during the earlier discovery step.
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
bool cryptoReady = false;

void parse_bitchat_packet(const uint8_t* data, size_t len);
void handle_fragment(const uint8_t* payload, uint16_t payloadLength);
void scan_callback(ble_gap_evt_adv_report_t* report);
void connect_callback(uint16_t conn_handle);
void notify_callback(
  BLEClientCharacteristic* chr,
  uint8_t* data,
  uint16_t len
);
void disconnect_callback(uint16_t conn_handle, uint8_t reason);

uint16_t readBE16(const uint8_t* p)
{
  return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t readBE32(const uint8_t* p)
{
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) |
         p[3];
}

uint64_t readBE64(const uint8_t* p)
{
  uint64_t value = 0;

  for (uint8_t i = 0; i < 8; i++)
  {
    value = (value << 8) | p[i];
  }

  return value;
}

void printUInt64(uint64_t value)
{
  char buffer[21];
  uint8_t position = sizeof(buffer) - 1;
  buffer[position] = '\0';

  do
  {
    buffer[--position] = '0' + (value % 10);
    value /= 10;
  }
  while (value > 0);

  Serial.print(buffer + position);
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

const char* messageTypeName(uint8_t type)
{
  switch (type)
  {
    case 0x01: return "ANNOUNCE";
    case 0x02: return "MESSAGE";
    case 0x03: return "LEAVE";
    case 0x04: return "COURIER_ENVELOPE";
    case 0x10: return "NOISE_HANDSHAKE";
    case 0x11: return "NOISE_ENCRYPTED";
    case 0x20: return "FRAGMENT";
    case 0x21: return "REQUEST_SYNC";
    case 0x22: return "FILE_TRANSFER";
    case 0x23: return "BOARD_POST";
    case 0x24: return "PREKEY_BUNDLE";
    case 0x25: return "GROUP_MESSAGE";
    case 0x2C: return "ANNOUNCE_V2";
    default: return "UNKNOWN";
  }
}

void printText(const uint8_t* data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    uint8_t value = data[i];

    if (value >= 0x20 && value <= 0x7E)
    {
      Serial.write(value);
    }
    else
    {
      Serial.print("\\x");
      if (value < 0x10) Serial.print('0');
      Serial.print(value, HEX);
    }
  }
}

void printCapabilities(const uint8_t* data, size_t len)
{
  uint64_t capabilities = 0;
  size_t decodedLength = len < 8 ? len : 8;

  for (size_t i = 0; i < decodedLength; i++)
  {
    capabilities |= ((uint64_t)data[i]) << (8 * i);
  }

  Serial.print("0x");
  printHex(data, len);
  Serial.print(" [");

  bool printed = false;
  const char* names[] = {
    "prekeys",
    "wifiBulk",
    "gateway",
    "groups",
    "board",
    "vouch",
    "meshDiagnostics",
    "bridge",
    "privateMedia",
    "privateMediaReceipts",
    "nonDestructiveNoiseReplacement"
  };

  for (uint8_t bit = 0; bit < 11; bit++)
  {
    if ((capabilities & ((uint64_t)1 << bit)) == 0) continue;

    if (printed) Serial.print(", ");
    Serial.print(names[bit]);
    printed = true;
  }

  uint64_t knownMask = (((uint64_t)1 << 11) - 1);
  if ((capabilities & ~knownMask) != 0)
  {
    if (printed) Serial.print(", ");
    Serial.print("unknown bits");
    printed = true;
  }

  if (!printed) Serial.print("none");
  Serial.println("]");
}

size_t signingDataLengthWithPadding(size_t unpaddedLength)
{
  static const size_t blockSizes[] = { 256, 512, 1024, 2048 };

  for (size_t i = 0; i < sizeof(blockSizes) / sizeof(blockSizes[0]); i++)
  {
    size_t blockSize = blockSizes[i];

    if (unpaddedLength + 16 <= blockSize)
    {
      size_t paddingLength = blockSize - unpaddedLength;

      // Bitchat padding uses one byte to store the padding length.
      if (paddingLength > 0 && paddingLength <= 255)
      {
        return blockSize;
      }

      return unpaddedLength;
    }
  }

  return unpaddedLength;
}

void verifyBitchatSignature(
  const uint8_t* packet,
  size_t signatureOffset,
  const uint8_t* signature,
  const uint8_t* signingPublicKey
)
{
  Serial.print("Signature verification: ");

  if (!cryptoReady)
  {
    Serial.println("UNAVAILABLE (CryptoCell initialization failed)");
    return;
  }

  size_t signingLength = signingDataLengthWithPadding(signatureOffset);
  if (signingLength > MAX_SIGNING_DATA)
  {
    Serial.println("SKIPPED (signing data exceeds buffer)");
    return;
  }

  static uint8_t signingData[MAX_SIGNING_DATA];
  static CRYS_ECEDW_TempBuff_t tempBuffer;

  memcpy(signingData, packet, signatureOffset);

  // Bitchat signs a packet with mutable relay fields normalized.
  signingData[2] = 0;
  uint8_t canonicalFlags = signingData[11] & (0x01 | 0x04);
  if (signingData[0] >= 2)
  {
    canonicalFlags |= signingData[11] & 0x08;
  }
  signingData[11] = canonicalFlags;

  if (signingLength > signatureOffset)
  {
    size_t paddingLength = signingLength - signatureOffset;
    memset(
      signingData + signatureOffset,
      (uint8_t)paddingLength,
      paddingLength
    );
  }

  memset(&tempBuffer, 0, sizeof(tempBuffer));

  CRYSError_t result = CRYS_ECEDW_Verify(
    signature,
    64,
    signingPublicKey,
    32,
    signingData,
    signingLength,
    &tempBuffer
  );

  if (result == CRYS_OK)
  {
    Serial.print("VALID (signed data: ");
    Serial.print(signingLength);
    Serial.println(" bytes)");
    return;
  }

  Serial.print("INVALID (CryptoCell error: 0x");
  Serial.print((uint32_t)result, HEX);
  Serial.println(")");
}

bool parseAnnouncePayload(
  const uint8_t* payload,
  size_t payloadLength,
  uint8_t* signingPublicKey
)
{
  bool hasNickname = false;
  bool hasNoisePublicKey = false;
  bool hasSigningPublicKey = false;
  size_t offset = 0;

  memset(signingPublicKey, 0, 32);

  Serial.println("--- ANNOUNCE PAYLOAD ---");

  while (offset + 2 <= payloadLength)
  {
    uint8_t tlvType = payload[offset++];
    uint8_t tlvLength = payload[offset++];

    if (offset + tlvLength > payloadLength)
    {
      Serial.print("Malformed TLV 0x");
      if (tlvType < 0x10) Serial.print('0');
      Serial.print(tlvType, HEX);
      Serial.println(": value exceeds payload");
      return false;
    }

    const uint8_t* value = payload + offset;

    switch (tlvType)
    {
      case 0x01:
        Serial.print("Nickname: ");
        printText(value, tlvLength);
        Serial.println();
        hasNickname = true;
        break;

      case 0x02:
        Serial.print("Noise public key (X25519) [");
        Serial.print(tlvLength);
        Serial.print(" bytes]: ");
        printHex(value, tlvLength);
        Serial.println();
        hasNoisePublicKey = tlvLength == 32;
        break;

      case 0x03:
        Serial.print("Signing public key (Ed25519) [");
        Serial.print(tlvLength);
        Serial.print(" bytes]: ");
        printHex(value, tlvLength);
        Serial.println();
        hasSigningPublicKey = tlvLength == 32;
        if (hasSigningPublicKey)
        {
          memcpy(signingPublicKey, value, 32);
        }
        break;

      case 0x04:
        Serial.print("Direct neighbors: ");
        if (tlvLength == 0 || (tlvLength % 8) != 0)
        {
          Serial.println("invalid length");
          break;
        }

        Serial.println(tlvLength / 8);
        for (uint8_t i = 0; i < tlvLength / 8; i++)
        {
          Serial.print("  - ");
          printHex(value + (i * 8), 8);
          Serial.println();
        }
        break;

      case 0x05:
        Serial.print("Capabilities: ");
        printCapabilities(value, tlvLength);
        break;

      case 0x06:
        Serial.print("Bridge geohash: ");
        printText(value, tlvLength);
        Serial.println();
        break;

      default:
        Serial.print("Unknown TLV 0x");
        if (tlvType < 0x10) Serial.print('0');
        Serial.print(tlvType, HEX);
        Serial.print(" [");
        Serial.print(tlvLength);
        Serial.print(" bytes]: ");
        printHex(value, tlvLength);
        Serial.println();
        break;
    }

    offset += tlvLength;
  }

  if (offset != payloadLength)
  {
    Serial.println("Malformed TLV payload: trailing byte");
    return false;
  }

  bool hasRequiredFields =
    hasNickname && hasNoisePublicKey && hasSigningPublicKey;

  Serial.print("Required fields: ");
  Serial.println(hasRequiredFields ? "present" : "missing or invalid");

  return hasRequiredFields;
}

void parse_bitchat_packet(const uint8_t* data, size_t len)
{
  if (len < 22)
  {
    Serial.println("Packet too short");
    return;
  }

  uint8_t version = data[0];
  uint8_t type = data[1];
  uint8_t ttl = data[2];
  uint8_t flags = data[11];

  if (version != 1 && version != 2)
  {
    Serial.print("Unsupported version: ");
    Serial.println(version);
    return;
  }

  size_t headerSize = version == 1 ? 14 : 16;
  if (len < headerSize + 8)
  {
    Serial.println("Packet header is incomplete");
    return;
  }

  uint32_t payloadLength = version == 1
    ? readBE16(data + 12)
    : readBE32(data + 12);

  size_t offset = headerSize;
  const uint8_t* senderId = data + offset;
  offset += 8;

  Serial.println();
  Serial.println("=== BITCHAT PACKET ===");

  Serial.print("Version: ");
  Serial.println(version);

  Serial.print("Type: ");
  Serial.print(messageTypeName(type));
  Serial.print(" (0x");
  if (type < 0x10) Serial.print('0');
  Serial.print(type, HEX);
  Serial.println(")");

  Serial.print("TTL: ");
  Serial.println(ttl);

  Serial.print("Timestamp (ms): ");
  printUInt64(readBE64(data + 3));
  Serial.println();

  Serial.print("Flags: 0x");
  if (flags < 0x10) Serial.print('0');
  Serial.println(flags, HEX);

  Serial.print("Payload length: ");
  Serial.println(payloadLength);

  Serial.print("Sender ID: ");
  printHex(senderId, 8);
  Serial.println();

  // Variable sections begin after the fixed header and sender ID.
  size_t payloadOffset = offset;

  if (flags & 0x01)
  {
    // A directed packet includes an 8-byte recipient ID.
    if (payloadOffset + 8 > len)
    {
      Serial.println("Recipient ID is incomplete");
      return;
    }

    Serial.print("Recipient ID: ");
    printHex(data + payloadOffset, 8);
    Serial.println();
    payloadOffset += 8;
  }

  if (version == 2 && (flags & 0x08))
  {
    if (payloadOffset >= len)
    {
      Serial.println("Route is incomplete");
      return;
    }

    uint8_t routeCount = data[payloadOffset++];
    size_t routeLength = (size_t)routeCount * 8;

    if (payloadOffset + routeLength > len)
    {
      Serial.println("Route hops are incomplete");
      return;
    }

    Serial.print("Route hops: ");
    Serial.println(routeCount);
    for (uint8_t i = 0; i < routeCount; i++)
    {
      Serial.print("  - ");
      printHex(data + payloadOffset + ((size_t)i * 8), 8);
      Serial.println();
    }

    payloadOffset += routeLength;
  }

  if (payloadLength > len - payloadOffset)
  {
    Serial.println("Incomplete packet");
    return;
  }

  const uint8_t* payload = data + payloadOffset;
  size_t packetEnd = payloadOffset + payloadLength;
  size_t signatureOffset = packetEnd;
  const uint8_t* signature = NULL;
  uint8_t announceSigningPublicKey[32];
  bool announceFieldsValid = false;

  if (flags & 0x02)
  {
    if (packetEnd + 64 > len)
    {
      Serial.println("Signature is incomplete");
      return;
    }

    signature = data + packetEnd;
    packetEnd += 64;
  }

  if (packetEnd < len)
  {
    Serial.print("Trailing bytes: ");
    Serial.println(len - packetEnd);
  }

  // Fragment
  if (type == 0x20)
  {
    if (payloadLength < 13)
    {
      Serial.println("Invalid fragment");
      return;
    }

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

    Serial.print("Original type: ");
    Serial.print(messageTypeName(payload[12]));
    Serial.print(" (0x");
    if (payload[12] < 0x10) Serial.print('0');
    Serial.print(payload[12], HEX);
    Serial.println(")");

    Serial.print("Fragment data length: ");
    Serial.println(payloadLength - 13);

    // Store the fragment for reassembly.
    handle_fragment(
      payload,
      payloadLength
    );

    return;
  }

  if (flags & 0x04)
  {
    Serial.println("Compressed payload decoding is not implemented");
  }
  else if (type == 0x01)
  {
    announceFieldsValid = parseAnnouncePayload(
      payload,
      payloadLength,
      announceSigningPublicKey
    );
  }

  if (signature != NULL)
  {
    Serial.print("Signature (Ed25519) [64 bytes]: ");
    printHex(signature, 64);
    Serial.println();
  }

  if (type == 0x01)
  {
    if (signature == NULL)
    {
      Serial.println("Signature verification: MISSING");
    }
    else if (flags & 0x04)
    {
      Serial.println("Signature verification: SKIPPED (compressed announce)");
    }
    else if (!announceFieldsValid)
    {
      Serial.println(
        "Signature verification: SKIPPED (signing public key missing)"
      );
    }
    else
    {
      verifyBitchatSignature(
        data,
        signatureOffset,
        signature,
        announceSigningPublicKey
      );
    }
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
  // 1 byte original message type

  if (payloadLength < 13)
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

  uint8_t originalType = payload[12];

  const uint8_t* fragmentData = payload + 13;

  uint16_t fragmentDataLength =
    payloadLength - 13;

  Serial.print("Fragment received: ");
  Serial.print(index);
  Serial.print(" / ");
  Serial.println(total);

  // Development-time upper bound.
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

  // Discard an assembly that has been inactive for more than 30 seconds.
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

  // Start a new fragment ID.
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
    fragmentAssembly.originalType = originalType;
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

  if (fragmentAssembly.originalType != originalType)
  {
    Serial.println("Fragment original type mismatch");
    resetFragmentAssembly();
    return;
  }

  // Ignore a duplicate fragment index.
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

  // Count the received fragments.
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
  // All fragments are present.
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

  if (
    reassembledLength < 2 ||
    reassembled[1] != fragmentAssembly.originalType
  )
  {
    Serial.println("Reassembled packet type does not match fragment metadata");
    resetFragmentAssembly();
    return;
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

  // Release the assembly before recursively parsing the inner packet.
  resetFragmentAssembly();

  // Parse the reassembled original Bitchat packet.
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

  // Configure one central connection.
  Bluefruit.begin(0, 1);

  cryptoReady = nRFCrypto.begin();
  Serial.print("Ed25519 verifier: ");
  Serial.println(cryptoReady ? "READY" : "FAILED");

  Bluefruit.setName("XIAO-Bitchat");

  // Register the client service and characteristic.
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

  // Connect to the device from this scan report.
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

  // Request the larger MTU after GATT discovery has completed.
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
