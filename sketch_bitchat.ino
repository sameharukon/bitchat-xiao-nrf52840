#include <bluefruit.h>
#include <Adafruit_nRFCrypto.h>
#include <Adafruit_LittleFS.h>
#include <InternalFileSystem.h>
#include <nrf_cc310/include/crys_ec_edw_api.h>
#include <nrf_cc310/include/crys_ec_mont_api.h>

using namespace Adafruit_LittleFS_Namespace;

#define MAX_FRAGMENTS      16
#define FRAGMENT_ASSEMBLY_SLOTS 2
#define MAX_FRAGMENT_DATA  480
#define MAX_REASSEMBLED    8192
#define MAX_SIGNING_DATA   2048
#define MAX_ANNOUNCE_PACKET 256
#define MAX_REQUEST_SYNC_GCS 1024
#define MAX_NICKNAME_BYTES 255
#define MAX_VERIFIED_PEERS 8
#define SEEN_PUBLIC_MESSAGE_RING_SIZE 64
#define MAX_LOCAL_MESSAGE_BYTES 1024
#define MAX_LOCAL_MESSAGE_PACKET (14 + 8 + MAX_LOCAL_MESSAGE_BYTES + 64)
#define LOCAL_MESSAGE_CACHE_SIZE 4
#define IDENTITY_RECORD_DATA_SIZE 72
#define IDENTITY_RECORD_SIZE 104

// Set to 0 after the one-shot RSR response path has been verified on hardware.
#define FORCE_REQUEST_SYNC_MISSING_TEST 0

static const char LOCAL_NICKNAME[] = "xiao52840";
static const uint32_t ANNOUNCE_INTERVAL_MS = 20000;
static const uint32_t ANNOUNCE_RETRY_MS = 1000;
static const uint32_t REQUEST_SYNC_RESPONSE_WINDOW_MS = 30000;
static const uint8_t REQUEST_SYNC_RESPONSE_LIMIT = 8;
// Matches upstream bleFragmentSpacingMs for broadcast fragments.
static const uint32_t FRAGMENT_SPACING_MS = 30;
static const size_t MIN_FRAGMENT_CHUNK = 64;
// Upstream messageTTLDefault. A peer's own announcement arrives with this TTL
// on a direct link; relayed copies arrive with a lower TTL.
static const uint8_t DIRECT_ANNOUNCE_TTL = 7;
// Matches upstream BLEPacketFreshnessPolicy.defaultMaxAgeSeconds.
static const uint64_t ANNOUNCE_MAX_AGE_MS = 900ULL * 1000;
// Matches the upstream public-message acceptance and gossip-sync window.
static const uint64_t PUBLIC_MESSAGE_MAX_AGE_MS = 6ULL * 60 * 60 * 1000;
static const char IDENTITY_FILE_PATH[] = "/bitchat_identity.bin";
static const char IDENTITY_TEMP_FILE_PATH[] = "/bitchat_identity.tmp";
static const uint8_t IDENTITY_RECORD_MAGIC[4] = {
  'B', 'C', 'I', 'D'
};
static const uint8_t IDENTITY_RECORD_VERSION = 1;

struct LocalIdentity
{
  bool ready;
  uint8_t noisePrivateKey[32];
  uint8_t noisePublicKey[32];
  uint8_t signingSecretKey[64];
  uint8_t signingPublicKey[32];
  uint8_t senderId[8];
};

struct VerifiedPeerIdentity
{
  bool ready;
  uint8_t senderId[8];
  uint8_t signingPublicKey[32];
  uint8_t nickname[MAX_NICKNAME_BYTES];
  uint8_t nicknameLength;
  uint32_t lastSeenAt;
};

enum VerifiedPeerUpdate
{
  VERIFIED_PEER_ADDED,
  VERIFIED_PEER_REFRESHED,
  VERIFIED_PEER_KEY_MISMATCH,
  VERIFIED_PEER_LOCK_TIMEOUT
};

struct LocalMessageEntry
{
  bool used;
  uint32_t sequence;
  uint64_t timestamp;
  uint8_t packetId[16];
  uint16_t packetLength;
  uint8_t packet[MAX_LOCAL_MESSAGE_PACKET];
};

struct RequestSyncPayload
{
  uint8_t p;
  uint32_t m;
  const uint8_t* gcsData;
  uint16_t gcsLength;
  uint64_t types;
  bool hasTypes;
  bool hasSinceTimestamp;
  uint64_t sinceTimestamp;
};

struct FragmentAssembly
{
  bool active;

  uint8_t senderId[8];
  uint8_t id[8];
  uint8_t originalType;

  uint16_t total;

  bool received[MAX_FRAGMENTS];

  uint16_t lengths[MAX_FRAGMENTS];

  uint8_t parts[MAX_FRAGMENTS][MAX_FRAGMENT_DATA];

  uint32_t startedAt;
};

// Assemblies are keyed by sender ID and fragment ID, so a relayed fragment
// stream from another peer does not discard the direct peer's assembly.
FragmentAssembly fragmentAssemblies[FRAGMENT_ASSEMBLY_SLOTS];

// Packet IDs of public messages that passed authentication. Only accessed from
// the notification processing path, like the fragment assembly.
uint8_t seenPublicMessageIds[SEEN_PUBLIC_MESSAGE_RING_SIZE][16];
uint8_t seenPublicMessageCount = 0;
uint8_t seenPublicMessageNext = 0;

// Recently transmitted local public messages, retained for sync responses.
// Shared between the Arduino loop and BLE callbacks under protocolStateMutex.
LocalMessageEntry localMessages[LOCAL_MESSAGE_CACHE_SIZE];
uint8_t localMessageNext = 0;
uint32_t localMessageSequence = 0;
uint8_t localMessageResponsePendingMask = 0;

LocalIdentity localIdentity;
// Signature-verified peers, keyed by sender ID. A signing key is pinned on first
// use and never silently replaced, matching upstream BLEAnnounceTrustPolicy.
VerifiedPeerIdentity verifiedPeers[MAX_VERIFIED_PEERS];
SemaphoreHandle_t cryptoMutex = NULL;
SemaphoreHandle_t protocolStateMutex = NULL;

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
bool identityFileSystemReady = false;
volatile bool bitchatLinkReady = false;
volatile uint8_t bitchatCharacteristicProperties = 0;
volatile uint16_t bitchatLinkMtu = 23;
volatile bool localAnnouncePending = false;
volatile bool localAnnounceSent = false;
volatile uint32_t lastLocalAnnounceSentAt = 0;
uint32_t lastLocalAnnounceAttemptAt = 0;
volatile bool requestSyncResponsePending = false;
uint32_t lastRequestSyncResponseAttemptAt = 0;
uint32_t requestSyncResponseWindowStartedAt = 0;
uint8_t requestSyncResponseCount = 0;
uint8_t lastLocalAnnouncePacket[MAX_ANNOUNCE_PACKET];
size_t lastLocalAnnouncePacketLength = 0;

volatile uint32_t clockGeneration = 0;
volatile uint32_t clockEpochHigh = 0;
volatile uint32_t clockEpochLow = 0;
volatile uint32_t clockMillisAtSync = 0;
volatile bool clockSynced = false;

void parse_bitchat_packet(const uint8_t* data, size_t len);
void evaluateLocalMessageSync(const RequestSyncPayload& request);
void handle_fragment(
  const uint8_t* senderId,
  const uint8_t* payload,
  uint16_t payloadLength
);
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

void writeBE16(uint8_t* p, uint16_t value)
{
  p[0] = (uint8_t)(value >> 8);
  p[1] = (uint8_t)value;
}

void writeBE64(uint8_t* p, uint64_t value)
{
  for (int8_t i = 7; i >= 0; i--)
  {
    p[7 - i] = (uint8_t)(value >> (i * 8));
  }
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

void secureZero(void* data, size_t length)
{
  volatile uint8_t* bytes = static_cast<volatile uint8_t*>(data);

  while (length > 0)
  {
    *bytes++ = 0;
    length--;
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

bool calculateSha256Parts(
  const uint8_t* const* parts,
  const size_t* lengths,
  size_t partCount,
  uint8_t* digest
)
{
  static nRFCrypto_Hash hash;

  if (
    cryptoMutex == NULL ||
    xSemaphoreTake(cryptoMutex, pdMS_TO_TICKS(1000)) != pdTRUE
  )
  {
    return false;
  }

  bool success = hash.begin(CRYS_HASH_SHA256_mode);
  for (size_t i = 0; success && i < partCount; i++)
  {
    if (lengths[i] == 0)
    {
      continue;
    }

    // The nRFCrypto API does not mark the input as const but does not modify it.
    success = hash.update(const_cast<uint8_t*>(parts[i]), lengths[i]);
  }

  if (success)
  {
    success = hash.end(digest) == 32;
  }

  xSemaphoreGive(cryptoMutex);
  return success;
}

bool calculateSha256(const uint8_t* data, size_t length, uint8_t* digest)
{
  return calculateSha256Parts(&data, &length, 1, digest);
}

bool takeCryptoMutex()
{
  if (
    cryptoMutex == NULL ||
    xSemaphoreTake(cryptoMutex, pdMS_TO_TICKS(1000)) != pdTRUE
  )
  {
    return false;
  }

  return true;
}

bool verifyBitchatSignature(
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
    return false;
  }

  size_t signingLength = signingDataLengthWithPadding(signatureOffset);
  if (signingLength > MAX_SIGNING_DATA)
  {
    Serial.println("SKIPPED (signing data exceeds buffer)");
    return false;
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

  if (!takeCryptoMutex())
  {
    Serial.println("SKIPPED (CryptoCell lock timeout)");
    return false;
  }

  CRYSError_t result = CRYS_ECEDW_Verify(
    signature,
    64,
    signingPublicKey,
    32,
    signingData,
    signingLength,
    &tempBuffer
  );

  xSemaphoreGive(cryptoMutex);

  if (result == CRYS_OK)
  {
    Serial.print("VALID (signed data: ");
    Serial.print(signingLength);
    Serial.println(" bytes)");
    return true;
  }

  Serial.print("INVALID (CryptoCell error: 0x");
  Serial.print((uint32_t)result, HEX);
  Serial.println(")");
  return false;
}

bool verifyNoiseKeySenderId(
  const uint8_t* senderId,
  uint8_t* noisePublicKey
)
{
  Serial.print("Derived Sender ID: ");

  if (!cryptoReady)
  {
    Serial.println("UNAVAILABLE");
    Serial.println("Sender ID verification: UNAVAILABLE");
    return false;
  }

  uint8_t digest[64];

  if (!calculateSha256(noisePublicKey, 32, digest))
  {
    Serial.println("HASH ERROR");
    Serial.println("Sender ID verification: ERROR");
    return false;
  }

  printHex(digest, 8);
  Serial.println();

  bool matches = memcmp(senderId, digest, 8) == 0;
  Serial.print("Sender ID verification: ");
  Serial.println(matches ? "VALID" : "INVALID");
  return matches;
}

bool validateIdentityRecord(const uint8_t* record)
{
  if (
    memcmp(record, IDENTITY_RECORD_MAGIC, sizeof(IDENTITY_RECORD_MAGIC)) != 0 ||
    record[4] != IDENTITY_RECORD_VERSION ||
    record[5] != 0 ||
    record[6] != 0 ||
    record[7] != 0
  )
  {
    return false;
  }

  uint8_t digest[64];
  bool hashCalculated = calculateSha256(
    record,
    IDENTITY_RECORD_DATA_SIZE,
    digest
  );
  bool valid = hashCalculated && memcmp(
    record + IDENTITY_RECORD_DATA_SIZE,
    digest,
    32
  ) == 0;

  secureZero(digest, sizeof(digest));
  return valid;
}

bool readIdentitySeeds(
  const char* path,
  uint8_t* noiseSeed,
  uint8_t* signingSeed
)
{
  File file(InternalFS);

  if (!file.open(path, FILE_O_READ))
  {
    return false;
  }

  uint8_t record[IDENTITY_RECORD_SIZE];
  bool correctSize = file.size() == IDENTITY_RECORD_SIZE;
  int32_t bytesRead = correctSize
    ? file.read(record, sizeof(record))
    : -1;
  file.close();

  if (
    !correctSize ||
    bytesRead != (int32_t)sizeof(record) ||
    !validateIdentityRecord(record)
  )
  {
    secureZero(record, sizeof(record));
    return false;
  }

  memcpy(noiseSeed, record + 8, 32);
  memcpy(signingSeed, record + 40, 32);
  secureZero(record, sizeof(record));
  return true;
}

bool writeIdentitySeeds(
  const uint8_t* noiseSeed,
  const uint8_t* signingSeed
)
{
  uint8_t record[IDENTITY_RECORD_SIZE];
  uint8_t digest[64];
  memset(record, 0, sizeof(record));
  memcpy(record, IDENTITY_RECORD_MAGIC, sizeof(IDENTITY_RECORD_MAGIC));
  record[4] = IDENTITY_RECORD_VERSION;
  memcpy(record + 8, noiseSeed, 32);
  memcpy(record + 40, signingSeed, 32);

  if (!calculateSha256(record, IDENTITY_RECORD_DATA_SIZE, digest))
  {
    secureZero(record, sizeof(record));
    secureZero(digest, sizeof(digest));
    return false;
  }

  memcpy(record + IDENTITY_RECORD_DATA_SIZE, digest, 32);
  secureZero(digest, sizeof(digest));

  if (InternalFS.exists(IDENTITY_TEMP_FILE_PATH))
  {
    InternalFS.remove(IDENTITY_TEMP_FILE_PATH);
  }

  File file(InternalFS);
  if (!file.open(IDENTITY_TEMP_FILE_PATH, FILE_O_WRITE))
  {
    secureZero(record, sizeof(record));
    return false;
  }

  size_t bytesWritten = file.write(record, sizeof(record));
  file.flush();
  file.close();
  secureZero(record, sizeof(record));

  if (bytesWritten != IDENTITY_RECORD_SIZE)
  {
    return false;
  }

  uint8_t verifiedNoiseSeed[32];
  uint8_t verifiedSigningSeed[32];
  bool tempValid = readIdentitySeeds(
    IDENTITY_TEMP_FILE_PATH,
    verifiedNoiseSeed,
    verifiedSigningSeed
  ) &&
    memcmp(noiseSeed, verifiedNoiseSeed, 32) == 0 &&
    memcmp(signingSeed, verifiedSigningSeed, 32) == 0;

  secureZero(verifiedNoiseSeed, sizeof(verifiedNoiseSeed));
  secureZero(verifiedSigningSeed, sizeof(verifiedSigningSeed));

  if (!tempValid)
  {
    return false;
  }

  if (!InternalFS.rename(IDENTITY_TEMP_FILE_PATH, IDENTITY_FILE_PATH))
  {
    return false;
  }

  bool finalValid = readIdentitySeeds(
    IDENTITY_FILE_PATH,
    verifiedNoiseSeed,
    verifiedSigningSeed
  ) &&
    memcmp(noiseSeed, verifiedNoiseSeed, 32) == 0 &&
    memcmp(signingSeed, verifiedSigningSeed, 32) == 0;

  secureZero(verifiedNoiseSeed, sizeof(verifiedNoiseSeed));
  secureZero(verifiedSigningSeed, sizeof(verifiedSigningSeed));
  return finalValid;
}

bool generateIdentitySeeds(uint8_t* noiseSeed, uint8_t* signingSeed)
{
  static nRFCrypto_Random random;

  if (!random.begin())
  {
    return false;
  }

  bool generated =
    random.generate(noiseSeed, 32) &&
    random.generate(signingSeed, 32);
  random.end();
  return generated;
}

bool deriveLocalIdentity(
  const uint8_t* noiseSeed,
  const uint8_t* signingSeed
)
{
  uint8_t digest[64];

  static CRYS_ECMONT_TempBuff_t noiseTempBuffer;
  static CRYS_ECEDW_TempBuff_t signingTempBuffer;
  memset(&noiseTempBuffer, 0, sizeof(noiseTempBuffer));
  memset(&signingTempBuffer, 0, sizeof(signingTempBuffer));

  size_t noisePublicKeySize = sizeof(localIdentity.noisePublicKey);
  size_t noisePrivateKeySize = sizeof(localIdentity.noisePrivateKey);
  CRYSError_t noiseResult = CRYS_ECMONT_SeedKeyPair(
    localIdentity.noisePublicKey,
    &noisePublicKeySize,
    localIdentity.noisePrivateKey,
    &noisePrivateKeySize,
    noiseSeed,
    32,
    &noiseTempBuffer
  );

  size_t signingSecretKeySize = sizeof(localIdentity.signingSecretKey);
  size_t signingPublicKeySize = sizeof(localIdentity.signingPublicKey);
  CRYSError_t signingResult = CRYS_ECEDW_SeedKeyPair(
    signingSeed,
    32,
    localIdentity.signingSecretKey,
    &signingSecretKeySize,
    localIdentity.signingPublicKey,
    &signingPublicKeySize,
    &signingTempBuffer
  );

  if (
    noiseResult != CRYS_OK ||
    noisePublicKeySize != 32 ||
    noisePrivateKeySize != 32 ||
    signingResult != CRYS_OK ||
    signingSecretKeySize != 64 ||
    signingPublicKeySize != 32 ||
    !calculateSha256(localIdentity.noisePublicKey, 32, digest)
  )
  {
    memset(&localIdentity, 0, sizeof(localIdentity));
    return false;
  }

  memcpy(localIdentity.senderId, digest, sizeof(localIdentity.senderId));
  memset(digest, 0, sizeof(digest));
  localIdentity.ready = true;

  return true;
}

bool initializeLocalIdentity()
{
  memset(&localIdentity, 0, sizeof(localIdentity));

  if (!cryptoReady || !identityFileSystemReady)
  {
    return false;
  }

  uint8_t noiseSeed[32];
  uint8_t signingSeed[32];
  bool loaded = false;
  bool created = false;

  if (InternalFS.exists(IDENTITY_FILE_PATH))
  {
    loaded = readIdentitySeeds(
      IDENTITY_FILE_PATH,
      noiseSeed,
      signingSeed
    );

    if (!loaded)
    {
      Serial.println("Local identity storage: INVALID");
      secureZero(noiseSeed, sizeof(noiseSeed));
      secureZero(signingSeed, sizeof(signingSeed));
      return false;
    }
  }
  else
  {
    // Recover a completely written temporary record after a power loss.
    if (InternalFS.exists(IDENTITY_TEMP_FILE_PATH))
    {
      loaded = readIdentitySeeds(
        IDENTITY_TEMP_FILE_PATH,
        noiseSeed,
        signingSeed
      );

      if (loaded)
      {
        loaded = InternalFS.rename(
          IDENTITY_TEMP_FILE_PATH,
          IDENTITY_FILE_PATH
        );
      }
      else
      {
        InternalFS.remove(IDENTITY_TEMP_FILE_PATH);
      }
    }

    if (!loaded)
    {
      bool generated = generateIdentitySeeds(noiseSeed, signingSeed);
      created = generated && writeIdentitySeeds(noiseSeed, signingSeed);

      if (!created)
      {
        Serial.println("Local identity storage: CREATE FAILED");
        secureZero(noiseSeed, sizeof(noiseSeed));
        secureZero(signingSeed, sizeof(signingSeed));
        return false;
      }
    }
  }

  bool derived = deriveLocalIdentity(noiseSeed, signingSeed);
  secureZero(noiseSeed, sizeof(noiseSeed));
  secureZero(signingSeed, sizeof(signingSeed));

  if (!derived)
  {
    return false;
  }

  Serial.print("Local identity storage: ");
  Serial.println(created ? "CREATED" : "LOADED");

  Serial.println("Local Bitchat identity: READY (persistent)");
  Serial.print("Local nickname: ");
  Serial.println(LOCAL_NICKNAME);
  Serial.print("Local Sender ID: ");
  printHex(localIdentity.senderId, sizeof(localIdentity.senderId));
  Serial.println();
  Serial.print("Local Noise public key: ");
  printHex(localIdentity.noisePublicKey, sizeof(localIdentity.noisePublicKey));
  Serial.println();
  Serial.print("Local signing public key: ");
  printHex(localIdentity.signingPublicKey, sizeof(localIdentity.signingPublicKey));
  Serial.println();

  return true;
}

void synchronizeClock(uint64_t epochMilliseconds)
{
  clockGeneration++;
  clockEpochHigh = (uint32_t)(epochMilliseconds >> 32);
  clockEpochLow = (uint32_t)epochMilliseconds;
  clockMillisAtSync = millis();
  clockSynced = true;
  clockGeneration++;
}

bool currentEpochMilliseconds(uint64_t* value)
{
  uint32_t generationBefore;
  uint32_t generationAfter;
  uint32_t epochHigh;
  uint32_t epochLow;
  uint32_t millisAtSync;
  bool isSynced;

  while (true)
  {
    generationBefore = clockGeneration;
    if (generationBefore & 1) continue;

    epochHigh = clockEpochHigh;
    epochLow = clockEpochLow;
    millisAtSync = clockMillisAtSync;
    isSynced = clockSynced;
    generationAfter = clockGeneration;

    if (
      generationBefore == generationAfter &&
      !(generationAfter & 1)
    )
    {
      break;
    }
  }

  if (!isSynced)
  {
    return false;
  }

  uint64_t epoch = ((uint64_t)epochHigh << 32) | epochLow;
  *value = epoch + (uint32_t)(millis() - millisAtSync);
  return true;
}

bool takeProtocolStateMutex()
{
  return protocolStateMutex != NULL &&
    xSemaphoreTake(protocolStateMutex, pdMS_TO_TICKS(100)) == pdTRUE;
}

VerifiedPeerIdentity* findVerifiedPeer(const uint8_t* senderId)
{
  for (uint8_t i = 0; i < MAX_VERIFIED_PEERS; i++)
  {
    if (
      verifiedPeers[i].ready &&
      memcmp(verifiedPeers[i].senderId, senderId, 8) == 0
    )
    {
      return &verifiedPeers[i];
    }
  }

  return NULL;
}

VerifiedPeerUpdate rememberVerifiedPeer(
  const uint8_t* senderId,
  const uint8_t* signingPublicKey,
  const uint8_t* nickname,
  uint8_t nicknameLength
)
{
  if (!takeProtocolStateMutex())
  {
    Serial.println("Verified peer cache: LOCK TIMEOUT");
    return VERIFIED_PEER_LOCK_TIMEOUT;
  }

  VerifiedPeerIdentity* peer = findVerifiedPeer(senderId);
  VerifiedPeerUpdate result = VERIFIED_PEER_REFRESHED;

  if (peer != NULL && memcmp(peer->signingPublicKey, signingPublicKey, 32) != 0)
  {
    xSemaphoreGive(protocolStateMutex);
    // The sender ID derives from the public Noise key, so anyone can pair it
    // with their own signing key and produce a valid self-signature.
    Serial.println(
      "Verified peer cache: REJECTED (signing key differs from pinned key; possible impersonation)"
    );
    return VERIFIED_PEER_KEY_MISMATCH;
  }

  if (peer == NULL)
  {
    result = VERIFIED_PEER_ADDED;

    // Use a free entry, or evict the least recently announced peer.
    peer = &verifiedPeers[0];
    for (uint8_t i = 0; i < MAX_VERIFIED_PEERS; i++)
    {
      if (!verifiedPeers[i].ready)
      {
        peer = &verifiedPeers[i];
        break;
      }

      if (
        (uint32_t)(millis() - verifiedPeers[i].lastSeenAt) >
        (uint32_t)(millis() - peer->lastSeenAt)
      )
      {
        peer = &verifiedPeers[i];
      }
    }

    if (peer->ready)
    {
      Serial.print("Verified peer cache: EVICTED ");
      printHex(peer->senderId, 8);
      Serial.println();
    }

    secureZero(peer, sizeof(*peer));
    memcpy(peer->senderId, senderId, 8);
    memcpy(peer->signingPublicKey, signingPublicKey, 32);
    peer->ready = true;
  }

  memcpy(peer->nickname, nickname, nicknameLength);
  peer->nicknameLength = nicknameLength;
  peer->lastSeenAt = millis();

  uint8_t count = 0;
  for (uint8_t i = 0; i < MAX_VERIFIED_PEERS; i++)
  {
    if (verifiedPeers[i].ready) count++;
  }
  xSemaphoreGive(protocolStateMutex);

  Serial.print("Verified peer cache: ");
  Serial.print(result == VERIFIED_PEER_ADDED ? "ADDED" : "REFRESHED");
  Serial.print(" (");
  Serial.print(count);
  Serial.print(" / ");
  Serial.print(MAX_VERIFIED_PEERS);
  Serial.println(")");
  return result;
}

bool getVerifiedPeer(
  const uint8_t* senderId,
  uint8_t* signingPublicKey,
  uint8_t* nickname,
  uint8_t* nicknameLength
)
{
  if (!takeProtocolStateMutex())
  {
    return false;
  }

  VerifiedPeerIdentity* peer = findVerifiedPeer(senderId);
  if (peer != NULL)
  {
    memcpy(signingPublicKey, peer->signingPublicKey, 32);

    if (nickname != NULL && nicknameLength != NULL)
    {
      memcpy(nickname, peer->nickname, peer->nicknameLength);
      *nicknameLength = peer->nicknameLength;
    }
  }

  xSemaphoreGive(protocolStateMutex);
  return peer != NULL;
}

bool getVerifiedPeerSigningKey(
  const uint8_t* senderId,
  uint8_t* signingPublicKey
)
{
  return getVerifiedPeer(senderId, signingPublicKey, NULL, NULL);
}

void cacheLocalAnnouncePacket(const uint8_t* packet, size_t packetLength)
{
  if (
    packetLength > sizeof(lastLocalAnnouncePacket) ||
    !takeProtocolStateMutex()
  )
  {
    return;
  }

  memcpy(lastLocalAnnouncePacket, packet, packetLength);
  lastLocalAnnouncePacketLength = packetLength;
  xSemaphoreGive(protocolStateMutex);
}

bool getCachedLocalAnnouncePacket(uint8_t* packet, size_t* packetLength)
{
  if (!takeProtocolStateMutex())
  {
    return false;
  }

  bool available =
    lastLocalAnnouncePacketLength > 0 &&
    lastLocalAnnouncePacketLength <= MAX_ANNOUNCE_PACKET;
  if (available)
  {
    memcpy(
      packet,
      lastLocalAnnouncePacket,
      lastLocalAnnouncePacketLength
    );
    *packetLength = lastLocalAnnouncePacketLength;
  }

  xSemaphoreGive(protocolStateMutex);
  return available;
}

// Official packet ID: SHA-256 prefix over type | sender ID | timestamp | payload.
bool calculatePacketIdFromFields(
  const uint8_t* type,
  const uint8_t* senderId,
  const uint8_t* timestamp,
  const uint8_t* payload,
  size_t payloadLength,
  uint8_t* packetId
)
{
  const uint8_t* parts[] = { type, senderId, timestamp, payload };
  size_t lengths[] = { 1, 8, 8, payloadLength };

  uint8_t digest[64];
  bool success = calculateSha256Parts(parts, lengths, 4, digest);
  if (success)
  {
    memcpy(packetId, digest, 16);
  }

  secureZero(digest, sizeof(digest));
  return success;
}

bool calculatePacketId(
  const uint8_t* packet,
  size_t packetLength,
  uint8_t* packetId
)
{
  if (packetLength < 22 || packet[0] != 1)
  {
    return false;
  }

  uint16_t payloadLength = readBE16(packet + 12);
  size_t payloadOffset = 22;
  if (packet[11] & 0x01)
  {
    payloadOffset += 8;
  }

  if (payloadOffset + payloadLength > packetLength)
  {
    return false;
  }

  return calculatePacketIdFromFields(
    packet + 1,
    packet + 14,
    packet + 3,
    packet + payloadOffset,
    payloadLength,
    packetId
  );
}

bool readGcsBit(
  const uint8_t* data,
  size_t dataLength,
  size_t* bitOffset,
  uint8_t* bit
)
{
  if (*bitOffset >= dataLength * 8)
  {
    return false;
  }

  size_t byteOffset = *bitOffset / 8;
  uint8_t shift = 7 - (*bitOffset % 8);
  *bit = (data[byteOffset] >> shift) & 1;
  (*bitOffset)++;
  return true;
}

bool gcsFilterMightContain(
  const RequestSyncPayload& request,
  const uint8_t* packetId
)
{
  if (
    request.p < 1 ||
    request.p > 32 ||
    request.m <= 1 ||
    request.gcsLength == 0
  )
  {
    return false;
  }

  uint8_t digest[64];
  if (!calculateSha256(packetId, 16, digest))
  {
    return false;
  }

  uint64_t hash = readBE64(digest) & 0x7FFFFFFFFFFFFFFFULL;
  secureZero(digest, sizeof(digest));
  uint64_t bucket = hash % request.m;
  if (bucket == 0)
  {
    bucket = 1;
  }

  size_t bitOffset = 0;
  uint64_t accumulator = 0;

  while (bitOffset < (size_t)request.gcsLength * 8)
  {
    uint64_t quotient = 0;
    uint8_t bit;

    while (true)
    {
      if (!readGcsBit(
            request.gcsData,
            request.gcsLength,
            &bitOffset,
            &bit
          ))
      {
        return false;
      }

      if (bit == 0)
      {
        break;
      }

      quotient++;
    }

    uint64_t remainder = 0;
    for (uint8_t i = 0; i < request.p; i++)
    {
      if (!readGcsBit(
            request.gcsData,
            request.gcsLength,
            &bitOffset,
            &bit
          ))
      {
        return false;
      }

      remainder = (remainder << 1) | bit;
    }

    uint64_t value = (quotient << request.p) + remainder + 1;
    if (UINT64_MAX - accumulator < value)
    {
      return false;
    }

    accumulator += value;
    if (accumulator == bucket)
    {
      return true;
    }

    if (accumulator > bucket || accumulator >= request.m)
    {
      return false;
    }
  }

  return false;
}

bool appendTlv(
  uint8_t* payload,
  size_t capacity,
  size_t* offset,
  uint8_t type,
  const uint8_t* value,
  size_t valueLength
)
{
  if (valueLength > 255 || *offset + 2 + valueLength > capacity)
  {
    return false;
  }

  payload[(*offset)++] = type;
  payload[(*offset)++] = (uint8_t)valueLength;
  memcpy(payload + *offset, value, valueLength);
  *offset += valueLength;
  return true;
}

// Signs a local version 1 packet in place. The 64-byte signature is written
// directly after the unsigned bytes, and the signature is verified before use.
bool signLocalPacket(
  uint8_t* packet,
  size_t unsignedLength,
  const char* label
)
{
  size_t signingLength = signingDataLengthWithPadding(unsignedLength);
  if (signingLength > MAX_SIGNING_DATA)
  {
    Serial.print("Local ");
    Serial.print(label);
    Serial.println(" signing error: signing data exceeds buffer");
    return false;
  }

  static uint8_t signingData[MAX_SIGNING_DATA];
  static CRYS_ECEDW_TempBuff_t signingTempBuffer;
  memcpy(signingData, packet, unsignedLength);
  signingData[2] = 0;
  signingData[11] &= (0x01 | 0x04);

  if (signingLength > unsignedLength)
  {
    size_t paddingLength = signingLength - unsignedLength;
    memset(
      signingData + unsignedLength,
      (uint8_t)paddingLength,
      paddingLength
    );
  }

  size_t signatureLength = 64;
  memset(&signingTempBuffer, 0, sizeof(signingTempBuffer));

  if (!takeCryptoMutex())
  {
    Serial.print("Local ");
    Serial.print(label);
    Serial.println(" signing error: CryptoCell lock timeout");
    return false;
  }

  CRYSError_t signResult = CRYS_ECEDW_Sign(
    packet + unsignedLength,
    &signatureLength,
    signingData,
    signingLength,
    localIdentity.signingSecretKey,
    sizeof(localIdentity.signingSecretKey),
    &signingTempBuffer
  );

  if (signResult != CRYS_OK || signatureLength != 64)
  {
    xSemaphoreGive(cryptoMutex);
    Serial.print("Local ");
    Serial.print(label);
    Serial.print(" signing error: 0x");
    Serial.println((uint32_t)signResult, HEX);
    return false;
  }

  memset(&signingTempBuffer, 0, sizeof(signingTempBuffer));
  CRYSError_t verifyResult = CRYS_ECEDW_Verify(
    packet + unsignedLength,
    64,
    localIdentity.signingPublicKey,
    sizeof(localIdentity.signingPublicKey),
    signingData,
    signingLength,
    &signingTempBuffer
  );

  xSemaphoreGive(cryptoMutex);

  Serial.print("Local ");
  Serial.print(label);
  Serial.print(" signature self-check: ");
  Serial.println(verifyResult == CRYS_OK ? "VALID" : "INVALID");
  return verifyResult == CRYS_OK;
}

bool buildLocalAnnounce(
  uint64_t timestamp,
  uint8_t* packet,
  size_t packetCapacity,
  size_t* packetLength
)
{
  if (!localIdentity.ready)
  {
    return false;
  }

  uint8_t payload[128];
  size_t payloadLength = 0;
  uint8_t noCapabilities = 0;

  if (
    !appendTlv(
      payload,
      sizeof(payload),
      &payloadLength,
      0x01,
      (const uint8_t*)LOCAL_NICKNAME,
      strlen(LOCAL_NICKNAME)
    ) ||
    !appendTlv(
      payload,
      sizeof(payload),
      &payloadLength,
      0x02,
      localIdentity.noisePublicKey,
      sizeof(localIdentity.noisePublicKey)
    ) ||
    !appendTlv(
      payload,
      sizeof(payload),
      &payloadLength,
      0x03,
      localIdentity.signingPublicKey,
      sizeof(localIdentity.signingPublicKey)
    ) ||
    !appendTlv(
      payload,
      sizeof(payload),
      &payloadLength,
      0x05,
      &noCapabilities,
      1
    )
  )
  {
    return false;
  }

  size_t unsignedLength = 14 + 8 + payloadLength;
  size_t totalLength = unsignedLength + 64;
  if (totalLength > packetCapacity || payloadLength > UINT16_MAX)
  {
    return false;
  }

  packet[0] = 1;
  packet[1] = 0x01;
  packet[2] = 7;
  writeBE64(packet + 3, timestamp);
  packet[11] = 0x02;
  writeBE16(packet + 12, (uint16_t)payloadLength);
  memcpy(packet + 14, localIdentity.senderId, 8);
  memcpy(packet + 22, payload, payloadLength);

  if (!signLocalPacket(packet, unsignedLength, "ANNOUNCE"))
  {
    return false;
  }

  *packetLength = totalLength;
  return true;
}

void requestLocalAnnounce()
{
  if (
    !localAnnounceSent ||
    millis() - lastLocalAnnounceSentAt >= 5000
  )
  {
    localAnnouncePending = true;
  }
}

bool generateRandomBytes(uint8_t* buffer, size_t length)
{
  static nRFCrypto_Random random;

  if (!takeCryptoMutex())
  {
    return false;
  }

  bool generated = random.begin();
  if (generated)
  {
    generated = random.generate(buffer, length);
    random.end();
  }

  xSemaphoreGive(cryptoMutex);
  return generated;
}

bool writeBitchatFrame(const uint8_t* frame, uint16_t frameLength)
{
  uint16_t written = 0;
  if (bitchatCharacteristicProperties & CHR_PROPS_WRITE_WO_RESP)
  {
    written = bitchatChar.write(frame, frameLength);
  }
  else if (bitchatCharacteristicProperties & CHR_PROPS_WRITE)
  {
    written = bitchatChar.write_resp(frame, frameLength);
  }

  Serial.print("GATT write: ");
  if (written == frameLength)
  {
    Serial.print("OK (");
    Serial.print(written);
    Serial.println(" bytes)");
    return true;
  }

  Serial.print("FAILED (");
  Serial.print(written);
  Serial.print(" / ");
  Serial.print(frameLength);
  Serial.println(" bytes)");
  return false;
}

// Writes a complete version 1 packet, splitting it into FRAGMENT packets when
// it does not fit in one ATT write. Each fragment repeats the original TTL,
// timestamp, sender, and RSR state, matching the upstream fragment planner.
bool transmitBitchatPacket(const uint8_t* packet, size_t packetLength)
{
  size_t maxWrite = bitchatLinkMtu > 3 ? bitchatLinkMtu - 3 : 0;

  if (packetLength <= maxWrite)
  {
    return writeBitchatFrame(packet, (uint16_t)packetLength);
  }

  // Version 1 header, sender ID, and the 13-byte fragment header.
  const size_t fragmentOverhead = 14 + 8 + 13;
  if (maxWrite < fragmentOverhead + MIN_FRAGMENT_CHUNK)
  {
    Serial.println("Fragmentation: FAILED (link MTU too small)");
    return false;
  }

  size_t chunkSize = maxWrite - fragmentOverhead;
  if (chunkSize > MAX_FRAGMENT_DATA)
  {
    chunkSize = MAX_FRAGMENT_DATA;
  }

  size_t total = (packetLength + chunkSize - 1) / chunkSize;
  if (total > MAX_FRAGMENTS)
  {
    Serial.println("Fragmentation: FAILED (too many fragments)");
    return false;
  }

  uint8_t fragmentId[8];
  if (!generateRandomBytes(fragmentId, sizeof(fragmentId)))
  {
    Serial.println("Fragmentation: FAILED (random fragment ID)");
    return false;
  }

  Serial.print("Fragmentation: ");
  Serial.print(total);
  Serial.print(" fragments, chunk ");
  Serial.print(chunkSize);
  Serial.print(" bytes, ID ");
  printHex(fragmentId, sizeof(fragmentId));
  Serial.println();

  static uint8_t frame[fragmentOverhead + MAX_FRAGMENT_DATA];
  for (size_t index = 0; index < total; index++)
  {
    size_t offset = index * chunkSize;
    size_t length = packetLength - offset < chunkSize
      ? packetLength - offset
      : chunkSize;
    uint16_t payloadLength = (uint16_t)(13 + length);

    frame[0] = 1;
    frame[1] = 0x20;
    frame[2] = packet[2];
    memcpy(frame + 3, packet + 3, 8);
    frame[11] = packet[11] & 0x10;
    writeBE16(frame + 12, payloadLength);
    memcpy(frame + 14, packet + 14, 8);
    memcpy(frame + 22, fragmentId, 8);
    writeBE16(frame + 30, (uint16_t)index);
    writeBE16(frame + 32, (uint16_t)total);
    frame[34] = packet[1];
    memcpy(frame + 35, packet + offset, length);

    if (index > 0)
    {
      delay(FRAGMENT_SPACING_MS);
    }

    if (!bitchatLinkReady || !writeBitchatFrame(frame, (uint16_t)(22 + payloadLength)))
    {
      Serial.print("Fragmentation: ABORTED at fragment ");
      Serial.println(index);
      return false;
    }
  }

  return true;
}

bool sendLocalAnnounce()
{
  if (!bitchatLinkReady || !localIdentity.ready)
  {
    return false;
  }

  uint64_t timestamp;
  if (!currentEpochMilliseconds(&timestamp))
  {
    return false;
  }

  uint8_t packet[MAX_ANNOUNCE_PACKET];
  size_t packetLength = 0;
  if (!buildLocalAnnounce(
        timestamp,
        packet,
        sizeof(packet),
        &packetLength
      ))
  {
    Serial.println("Local ANNOUNCE build: FAILED");
    return false;
  }

  Serial.println();
  Serial.println("=== LOCAL ANNOUNCE TX ===");
  Serial.print("Timestamp (ms): ");
  printUInt64(timestamp);
  Serial.println();
  Serial.print("Sender ID: ");
  printHex(localIdentity.senderId, sizeof(localIdentity.senderId));
  Serial.println();
  Serial.print("Packet length: ");
  Serial.println(packetLength);

  if (!transmitBitchatPacket(packet, packetLength))
  {
    return false;
  }

  localAnnouncePending = false;
  localAnnounceSent = true;
  lastLocalAnnounceSentAt = millis();
  cacheLocalAnnouncePacket(packet, packetLength);
  return true;
}

bool reserveRequestSyncResponse()
{
  uint32_t now = millis();
  if (
    requestSyncResponseWindowStartedAt == 0 ||
    now - requestSyncResponseWindowStartedAt >=
      REQUEST_SYNC_RESPONSE_WINDOW_MS
  )
  {
    requestSyncResponseWindowStartedAt = now;
    requestSyncResponseCount = 0;
  }

  if (requestSyncResponseCount >= REQUEST_SYNC_RESPONSE_LIMIT)
  {
    return false;
  }

  requestSyncResponseCount++;
  return true;
}

bool sendRequestSyncAnnounceResponse()
{
  if (!bitchatLinkReady || !localIdentity.ready)
  {
    return false;
  }

  uint8_t packet[MAX_ANNOUNCE_PACKET];
  size_t packetLength = 0;
  if (!getCachedLocalAnnouncePacket(packet, &packetLength))
  {
    Serial.println("REQUEST_SYNC response: no cached local ANNOUNCE");
    requestSyncResponsePending = false;
    return false;
  }

  // TTL and RSR are mutable relay fields and are excluded from the signature.
  packet[2] = 0;
  packet[11] |= 0x10;

  Serial.println();
  Serial.println("=== REQUEST_SYNC ANNOUNCE RESPONSE TX ===");
  Serial.print("Timestamp (ms): ");
  printUInt64(readBE64(packet + 3));
  Serial.println();
  Serial.print("Sender ID: ");
  printHex(localIdentity.senderId, sizeof(localIdentity.senderId));
  Serial.println();
  Serial.println("TTL: 0");
  Serial.println("Flags: 0x12 [signature, RSR]");

  if (!transmitBitchatPacket(packet, packetLength))
  {
    return false;
  }

  requestSyncResponsePending = false;
  lastLocalAnnounceSentAt = millis();
  return true;
}

void serviceRequestSyncResponse()
{
  if (!requestSyncResponsePending || !bitchatLinkReady)
  {
    return;
  }

  uint32_t now = millis();
  if (now - lastRequestSyncResponseAttemptAt < ANNOUNCE_RETRY_MS)
  {
    return;
  }

  lastRequestSyncResponseAttemptAt = now;
  sendRequestSyncAnnounceResponse();
}

void serviceLocalAnnounce()
{
  if (!bitchatLinkReady || !clockSynced || !localIdentity.ready)
  {
    return;
  }

  uint32_t now = millis();
  bool periodicDue =
    localAnnounceSent &&
    now - lastLocalAnnounceSentAt >= ANNOUNCE_INTERVAL_MS;

  if (!localAnnouncePending && !periodicDue)
  {
    return;
  }

  if (now - lastLocalAnnounceAttemptAt < ANNOUNCE_RETRY_MS)
  {
    return;
  }

  lastLocalAnnounceAttemptAt = now;
  sendLocalAnnounce();
}

void printRequestSyncTypes(uint64_t types)
{
  struct SyncTypeName
  {
    uint8_t bit;
    const char* name;
  };

  static const SyncTypeName names[] = {
    {0, "announce"},
    {1, "message"},
    {2, "leave"},
    {3, "noiseHandshake"},
    {4, "noiseEncrypted"},
    {5, "fragment"},
    {6, "requestSync"},
    {7, "fileTransfer"},
    {8, "boardPost"},
    {9, "prekeyBundle"},
    {10, "groupMessage"}
  };

  bool first = true;
  Serial.print('[');
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    if ((types & (1ULL << names[i].bit)) == 0)
    {
      continue;
    }

    if (!first)
    {
      Serial.print(", ");
    }
    Serial.print(names[i].name);
    first = false;
  }
  Serial.println(']');
}

bool parseRequestSyncPayload(
  const uint8_t* payload,
  size_t payloadLength,
  RequestSyncPayload* request
)
{
  memset(request, 0, sizeof(*request));
  bool hasP = false;
  bool hasM = false;
  bool hasGcsData = false;
  size_t offset = 0;

  Serial.println("--- REQUEST_SYNC PAYLOAD ---");

  while (offset + 3 <= payloadLength)
  {
    uint8_t type = payload[offset++];
    uint16_t length = readBE16(payload + offset);
    offset += 2;

    if (length > payloadLength - offset)
    {
      Serial.println("Malformed REQUEST_SYNC TLV: value exceeds payload");
      return false;
    }

    const uint8_t* value = payload + offset;
    switch (type)
    {
      case 0x01:
        if (length != 1)
        {
          Serial.println("P: invalid length");
          return false;
        }
        request->p = value[0];
        hasP = true;
        Serial.print("P: ");
        Serial.println(request->p);
        break;

      case 0x02:
        if (length != 4)
        {
          Serial.println("M: invalid length");
          return false;
        }
        request->m = readBE32(value);
        hasM = true;
        Serial.print("M: ");
        Serial.println(request->m);
        break;

      case 0x03:
        if (length > MAX_REQUEST_SYNC_GCS)
        {
          Serial.println("GCS data: exceeds acceptance limit");
          return false;
        }
        request->gcsData = value;
        request->gcsLength = length;
        hasGcsData = true;
        Serial.print("GCS data [");
        Serial.print(length);
        Serial.print(" bytes]: ");
        printHex(value, length);
        Serial.println();
        break;

      case 0x04:
        if (length < 1 || length > 8)
        {
          Serial.println("Types: invalid length");
          return false;
        }
        request->types = 0;
        for (uint8_t i = 0; i < length; i++)
        {
          request->types |= (uint64_t)value[i] << (i * 8);
        }
        request->hasTypes = true;
        Serial.print("Types raw: 0x");
        for (int16_t i = length - 1; i >= 0; i--)
        {
          if (value[i] < 0x10) Serial.print('0');
          Serial.print(value[i], HEX);
        }
        Serial.print(' ');
        printRequestSyncTypes(request->types);
        break;

      case 0x05:
        if (length != 8)
        {
          Serial.println("Since timestamp: invalid length");
          return false;
        }
        request->sinceTimestamp = readBE64(value);
        request->hasSinceTimestamp = true;
        Serial.print("Since timestamp (ms): ");
        printUInt64(request->sinceTimestamp);
        Serial.println();
        break;

      case 0x06:
        if (length <= MAX_REQUEST_SYNC_GCS)
        {
          Serial.print("Fragment ID filter: ");
          printText(value, length);
          Serial.println();
        }
        else
        {
          Serial.println("Fragment ID filter: ignored (too large)");
        }
        break;

      default:
        Serial.print("Unknown REQUEST_SYNC TLV 0x");
        if (type < 0x10) Serial.print('0');
        Serial.print(type, HEX);
        Serial.print(" [");
        Serial.print(length);
        Serial.println(" bytes]");
        break;
    }

    offset += length;
  }

  if (offset != payloadLength)
  {
    Serial.println("Malformed REQUEST_SYNC payload: trailing bytes");
    return false;
  }

  if (!request->hasTypes)
  {
    // Legacy requests cover public announcements and public messages.
    request->types = (1ULL << 0) | (1ULL << 1);
    Serial.print("Types default: ");
    printRequestSyncTypes(request->types);
  }

  bool valid =
    hasP &&
    hasM &&
    hasGcsData &&
    request->p >= 1 &&
    request->p <= 32 &&
    request->m > 0;
  Serial.print("REQUEST_SYNC fields: ");
  Serial.println(valid ? "VALID" : "INVALID");
  return valid;
}

void handleRequestSyncPacket(
  const uint8_t* packet,
  size_t signatureOffset,
  const uint8_t* signature,
  uint8_t ttl,
  const uint8_t* senderId,
  const uint8_t* recipientId,
  const uint8_t* payload,
  size_t payloadLength
)
{
  Serial.println("--- REQUEST_SYNC VALIDATION ---");

  if (ttl != 0)
  {
    Serial.println("REQUEST_SYNC rejected: TTL must be zero");
    return;
  }

  if (
    recipientId == NULL ||
    !localIdentity.ready ||
    memcmp(recipientId, localIdentity.senderId, 8) != 0
  )
  {
    Serial.println("REQUEST_SYNC rejected: recipient is not local identity");
    return;
  }
  Serial.println("Recipient verification: VALID");

  if (signature == NULL)
  {
    Serial.println("REQUEST_SYNC rejected: signature is missing");
    return;
  }

  uint8_t signingPublicKey[32];
  if (!getVerifiedPeerSigningKey(senderId, signingPublicKey))
  {
    Serial.println("REQUEST_SYNC rejected: sender has no verified ANNOUNCE");
    return;
  }

  bool signatureValid = verifyBitchatSignature(
    packet,
    signatureOffset,
    signature,
    signingPublicKey
  );
  secureZero(signingPublicKey, sizeof(signingPublicKey));
  if (!signatureValid)
  {
    return;
  }

  RequestSyncPayload request;
  if (!parseRequestSyncPayload(payload, payloadLength, &request))
  {
    return;
  }

  if (request.types & (1ULL << 1))
  {
    evaluateLocalMessageSync(request);
  }
  else
  {
    Serial.println("REQUEST_SYNC response: MESSAGE not requested");
  }

  if ((request.types & (1ULL << 0)) == 0)
  {
    Serial.println("REQUEST_SYNC response: ANNOUNCE not requested");
    return;
  }

  uint8_t announce[MAX_ANNOUNCE_PACKET];
  size_t announceLength = 0;
  if (!getCachedLocalAnnouncePacket(announce, &announceLength))
  {
    Serial.println("REQUEST_SYNC response: no cached local ANNOUNCE");
    return;
  }

  uint8_t packetId[16];
  bool idCalculated = calculatePacketId(
    announce,
    announceLength,
    packetId
  );
  bool alreadyPresent = idCalculated &&
    gcsFilterMightContain(request, packetId);
  bool forcedMissing = false;

#if FORCE_REQUEST_SYNC_MISSING_TEST
  static bool forcedMissingTestUsed = false;
  if (idCalculated && !forcedMissingTestUsed)
  {
    alreadyPresent = false;
    forcedMissing = true;
    forcedMissingTestUsed = true;
  }
#endif

  Serial.print("Local ANNOUNCE packet ID: ");
  if (idCalculated)
  {
    printHex(packetId, sizeof(packetId));
    Serial.println();
  }
  else
  {
    Serial.println("CALCULATION FAILED");
  }
  secureZero(packetId, sizeof(packetId));
  secureZero(announce, sizeof(announce));

  if (!idCalculated)
  {
    return;
  }

  Serial.print("GCS membership: ");
  if (forcedMissing)
  {
    Serial.println("FORCED MISSING (one-shot test)");
  }
  else
  {
    Serial.println(alreadyPresent ? "PRESENT" : "MISSING");
  }
  if (alreadyPresent)
  {
    Serial.println("REQUEST_SYNC response: not needed");
    return;
  }

  if (!reserveRequestSyncResponse())
  {
    Serial.println("REQUEST_SYNC response: RATE LIMITED");
    return;
  }

  requestSyncResponsePending = true;
  Serial.println("REQUEST_SYNC response: RSR ANNOUNCE QUEUED");
}

// Strict UTF-8 validation: rejects overlong forms, surrogates, and code points
// above U+10FFFF, matching what Foundation accepts as UTF-8 text.
bool isValidUtf8(const uint8_t* data, size_t length)
{
  size_t i = 0;

  while (i < length)
  {
    uint8_t lead = data[i];
    size_t continuationCount;
    uint8_t minSecond = 0x80;
    uint8_t maxSecond = 0xBF;

    if (lead <= 0x7F)
    {
      i++;
      continue;
    }
    else if (lead >= 0xC2 && lead <= 0xDF)
    {
      continuationCount = 1;
    }
    else if (lead >= 0xE0 && lead <= 0xEF)
    {
      continuationCount = 2;
      if (lead == 0xE0) minSecond = 0xA0;
      if (lead == 0xED) maxSecond = 0x9F;
    }
    else if (lead >= 0xF0 && lead <= 0xF4)
    {
      continuationCount = 3;
      if (lead == 0xF0) minSecond = 0x90;
      if (lead == 0xF4) maxSecond = 0x8F;
    }
    else
    {
      return false;
    }

    if (continuationCount > length - i - 1)
    {
      return false;
    }

    if (data[i + 1] < minSecond || data[i + 1] > maxSecond)
    {
      return false;
    }

    for (size_t j = 2; j <= continuationCount; j++)
    {
      if ((data[i + j] & 0xC0) != 0x80)
      {
        return false;
      }
    }

    i += continuationCount + 1;
  }

  return true;
}

void printEscapedCodePoint(uint32_t codePoint)
{
  Serial.print("\\u{");
  Serial.print(codePoint, HEX);
  Serial.print('}');
}

// Prints validated UTF-8 text. Control and bidirectional formatting characters
// are escaped so that peer-supplied text cannot alter the terminal or the
// visual order of the log.
void printSafeUtf8(const uint8_t* data, size_t length)
{
  size_t i = 0;

  while (i < length)
  {
    uint8_t lead = data[i];

    if (lead < 0x80)
    {
      if (lead == '\\')
      {
        Serial.print("\\\\");
      }
      else if (lead < 0x20 || lead == 0x7F)
      {
        Serial.print("\\x");
        if (lead < 0x10) Serial.print('0');
        Serial.print(lead, HEX);
      }
      else
      {
        Serial.write(lead);
      }

      i++;
      continue;
    }

    size_t sequenceLength = lead >= 0xF0 ? 4 : (lead >= 0xE0 ? 3 : 2);
    uint32_t codePoint = lead & (0x7F >> sequenceLength);
    for (size_t j = 1; j < sequenceLength; j++)
    {
      codePoint = (codePoint << 6) | (data[i + j] & 0x3F);
    }

    bool escape =
      (codePoint >= 0x80 && codePoint <= 0x9F) ||
      codePoint == 0x061C ||
      codePoint == 0x200E ||
      codePoint == 0x200F ||
      (codePoint >= 0x2028 && codePoint <= 0x202E) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069);

    if (escape)
    {
      printEscapedCodePoint(codePoint);
    }
    else
    {
      Serial.write(data + i, sequenceLength);
    }

    i += sequenceLength;
  }
}

void printPeerText(const uint8_t* data, size_t length)
{
  if (isValidUtf8(data, length))
  {
    printSafeUtf8(data, length);
  }
  else
  {
    printText(data, length);
  }
}

void printUtcTimestamp(uint64_t epochMilliseconds)
{
  uint64_t totalSeconds = epochMilliseconds / 1000;
  uint16_t milliseconds = (uint16_t)(epochMilliseconds % 1000);
  uint32_t secondOfDay = (uint32_t)(totalSeconds % 86400);
  int64_t days = (int64_t)(totalSeconds / 86400);

  // Civil date from days since 1970-01-01 (proleptic Gregorian calendar).
  days += 719468;
  int64_t era = days / 146097;
  uint32_t dayOfEra = (uint32_t)(days - era * 146097);
  uint32_t yearOfEra =
    (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
  int64_t year = (int64_t)yearOfEra + era * 400;
  uint32_t dayOfYear =
    dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
  uint32_t monthIndex = (5 * dayOfYear + 2) / 153;
  uint32_t day = dayOfYear - (153 * monthIndex + 2) / 5 + 1;
  uint32_t month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9;
  if (month <= 2) year++;

  char buffer[64];
  snprintf(
    buffer,
    sizeof(buffer),
    "%04ld-%02lu-%02luT%02lu:%02lu:%02lu.%03uZ",
    (long)year,
    (unsigned long)month,
    (unsigned long)day,
    (unsigned long)(secondOfDay / 3600),
    (unsigned long)((secondOfDay / 60) % 60),
    (unsigned long)(secondOfDay % 60),
    (unsigned)milliseconds
  );
  Serial.print(buffer);
}

bool isBroadcastRecipient(const uint8_t* recipientId)
{
  if (recipientId == NULL)
  {
    return true;
  }

  for (uint8_t i = 0; i < 8; i++)
  {
    if (recipientId[i] != 0xFF)
    {
      return false;
    }
  }

  return true;
}

bool publicMessageAlreadySeen(const uint8_t* packetId)
{
  for (uint8_t i = 0; i < seenPublicMessageCount; i++)
  {
    if (memcmp(seenPublicMessageIds[i], packetId, 16) == 0)
    {
      return true;
    }
  }

  return false;
}

void rememberPublicMessage(const uint8_t* packetId)
{
  memcpy(seenPublicMessageIds[seenPublicMessageNext], packetId, 16);
  seenPublicMessageNext =
    (seenPublicMessageNext + 1) % SEEN_PUBLIC_MESSAGE_RING_SIZE;

  if (seenPublicMessageCount < SEEN_PUBLIC_MESSAGE_RING_SIZE)
  {
    seenPublicMessageCount++;
  }
}

void handlePublicMessagePacket(
  const uint8_t* packet,
  size_t signatureOffset,
  const uint8_t* signature,
  uint8_t ttl,
  uint8_t flags,
  const uint8_t* senderId,
  const uint8_t* recipientId,
  const uint8_t* payload,
  size_t payloadLength
)
{
  Serial.println("--- PUBLIC MESSAGE VALIDATION ---");

  if (localIdentity.ready && memcmp(senderId, localIdentity.senderId, 8) == 0)
  {
    // The XIAO never sends REQUEST_SYNC, so no self-authored copy can be a
    // solicited sync response, and its own messages are already displayed.
    Serial.println(
      ttl != 0
        ? "MESSAGE rejected: self echo"
        : "MESSAGE rejected: unsolicited self-authored copy"
    );
    return;
  }

  bool broadcast = isBroadcastRecipient(recipientId);
  if (
    !broadcast &&
    (!localIdentity.ready || memcmp(recipientId, localIdentity.senderId, 8) != 0)
  )
  {
    Serial.println("MESSAGE rejected: addressed to another peer");
    return;
  }

  if (flags & 0x04)
  {
    Serial.println("MESSAGE rejected: compressed payload unsupported");
    return;
  }

  if (signature == NULL)
  {
    Serial.println("MESSAGE rejected: signature is missing");
    return;
  }

  uint8_t signingPublicKey[32];
  static uint8_t nickname[MAX_NICKNAME_BYTES];
  uint8_t nicknameLength = 0;
  if (!getVerifiedPeer(senderId, signingPublicKey, nickname, &nicknameLength))
  {
    Serial.println("MESSAGE rejected: sender has no verified ANNOUNCE");
    return;
  }

  uint64_t timestamp = readBE64(packet + 3);
  uint64_t now = 0;
  if (!currentEpochMilliseconds(&now))
  {
    secureZero(signingPublicKey, sizeof(signingPublicKey));
    Serial.println("MESSAGE rejected: clock is not synchronized");
    return;
  }

  // Upstream applies the freshness window to broadcast messages only.
  if (
    broadcast &&
    now >= PUBLIC_MESSAGE_MAX_AGE_MS &&
    timestamp < now - PUBLIC_MESSAGE_MAX_AGE_MS
  )
  {
    secureZero(signingPublicKey, sizeof(signingPublicKey));
    Serial.print("MESSAGE rejected: stale broadcast (age: ");
    printUInt64((now - timestamp) / 1000);
    Serial.println(" s)");
    return;
  }

  uint8_t packetId[16];
  if (!calculatePacketIdFromFields(
        packet + 1,
        senderId,
        packet + 3,
        payload,
        payloadLength,
        packetId
      ))
  {
    secureZero(signingPublicKey, sizeof(signingPublicKey));
    Serial.println("MESSAGE rejected: packet ID calculation failed");
    return;
  }

  Serial.print("Packet ID: ");
  printHex(packetId, sizeof(packetId));
  Serial.println();

  // Lookup before verification avoids repeated CryptoCell work, while only
  // authenticated packets are inserted so forged copies cannot poison the ring.
  if (publicMessageAlreadySeen(packetId))
  {
    secureZero(signingPublicKey, sizeof(signingPublicKey));
    Serial.println("MESSAGE suppressed: duplicate packet ID");
    return;
  }

  bool signatureValid = verifyBitchatSignature(
    packet,
    signatureOffset,
    signature,
    signingPublicKey
  );
  secureZero(signingPublicKey, sizeof(signingPublicKey));
  if (!signatureValid)
  {
    Serial.println("MESSAGE rejected: signature verification failed");
    return;
  }

  rememberPublicMessage(packetId);

  if (!isValidUtf8(payload, payloadLength))
  {
    Serial.println("MESSAGE rejected: payload is not valid UTF-8");
    return;
  }

  Serial.println();
  Serial.println(broadcast ? "--- PUBLIC MESSAGE ---" : "--- DIRECTED MESSAGE ---");
  Serial.print("Sender: ");
  printPeerText(nickname, nicknameLength);
  Serial.println();
  Serial.print("Sender ID: ");
  printHex(senderId, 8);
  Serial.println();
  Serial.print("Timestamp (ms): ");
  printUInt64(timestamp);
  Serial.print(" (");
  printUtcTimestamp(timestamp);
  Serial.println(")");
  Serial.print("TTL: ");
  Serial.println(ttl);
  Serial.print("Length: ");
  Serial.print(payloadLength);
  Serial.println(" bytes");
  Serial.println("Signature verification: VALID");
  Serial.print("Content: ");
  printSafeUtf8(payload, payloadLength);
  Serial.println();
}

bool sendLocalPublicMessage(const uint8_t* text, size_t textLength)
{
  if (!localIdentity.ready)
  {
    Serial.println("MESSAGE TX rejected: local identity unavailable");
    return false;
  }

  if (!bitchatLinkReady)
  {
    Serial.println("MESSAGE TX rejected: no Bitchat link");
    return false;
  }

  uint64_t timestamp;
  if (!currentEpochMilliseconds(&timestamp))
  {
    Serial.println(
      "MESSAGE TX rejected: clock is not synchronized (waiting for a verified ANNOUNCE)"
    );
    return false;
  }

  if (textLength == 0 || textLength > MAX_LOCAL_MESSAGE_BYTES)
  {
    Serial.println("MESSAGE TX rejected: invalid length");
    return false;
  }

  static uint8_t packet[MAX_LOCAL_MESSAGE_PACKET];
  size_t unsignedLength = 14 + 8 + textLength;
  size_t packetLength = unsignedLength + 64;

  packet[0] = 1;
  packet[1] = 0x02;
  packet[2] = 7;
  writeBE64(packet + 3, timestamp);
  packet[11] = 0x02;
  writeBE16(packet + 12, (uint16_t)textLength);
  memcpy(packet + 14, localIdentity.senderId, 8);
  memcpy(packet + 22, text, textLength);

  if (!signLocalPacket(packet, unsignedLength, "MESSAGE"))
  {
    return false;
  }

  uint8_t packetId[16];
  if (!calculatePacketIdFromFields(
        packet + 1,
        packet + 14,
        packet + 3,
        packet + 22,
        textLength,
        packetId
      ))
  {
    Serial.println("MESSAGE TX rejected: packet ID calculation failed");
    return false;
  }

  // Cache before writing so that a sync request arriving during a fragmented
  // write already sees the message.
  if (takeProtocolStateMutex())
  {
    LocalMessageEntry& entry = localMessages[localMessageNext];
    localMessageResponsePendingMask &= ~(1 << localMessageNext);
    entry.used = true;
    entry.sequence = ++localMessageSequence;
    entry.timestamp = timestamp;
    memcpy(entry.packetId, packetId, sizeof(packetId));
    entry.packetLength = (uint16_t)packetLength;
    memcpy(entry.packet, packet, packetLength);
    localMessageNext = (localMessageNext + 1) % LOCAL_MESSAGE_CACHE_SIZE;
    xSemaphoreGive(protocolStateMutex);
  }
  else
  {
    Serial.println("Local MESSAGE cache: LOCK TIMEOUT");
  }

  Serial.println();
  Serial.println("=== LOCAL PUBLIC MESSAGE TX ===");
  Serial.print("Sender: ");
  Serial.println(LOCAL_NICKNAME);
  Serial.print("Sender ID: ");
  printHex(localIdentity.senderId, sizeof(localIdentity.senderId));
  Serial.println();
  Serial.print("Timestamp (ms): ");
  printUInt64(timestamp);
  Serial.print(" (");
  printUtcTimestamp(timestamp);
  Serial.println(")");
  Serial.print("Packet ID: ");
  printHex(packetId, sizeof(packetId));
  Serial.println();
  Serial.print("Length: ");
  Serial.print(textLength);
  Serial.println(" bytes");
  Serial.print("Packet length: ");
  Serial.println(packetLength);
  Serial.print("Content: ");
  printSafeUtf8(text, textLength);
  Serial.println();

  return transmitBitchatPacket(packet, packetLength);
}

void evaluateLocalMessageSync(const RequestSyncPayload& request)
{
  struct Candidate
  {
    uint8_t slot;
    uint32_t sequence;
    uint64_t timestamp;
    uint8_t packetId[16];
  };

  Candidate candidates[LOCAL_MESSAGE_CACHE_SIZE];
  uint8_t candidateCount = 0;

  uint64_t now;
  if (!currentEpochMilliseconds(&now))
  {
    Serial.println("REQUEST_SYNC MESSAGE: clock is not synchronized");
    return;
  }

  if (!takeProtocolStateMutex())
  {
    Serial.println("REQUEST_SYNC MESSAGE: LOCK TIMEOUT");
    return;
  }

  for (uint8_t i = 0; i < LOCAL_MESSAGE_CACHE_SIZE; i++)
  {
    if (!localMessages[i].used)
    {
      continue;
    }

    Candidate& candidate = candidates[candidateCount++];
    candidate.slot = i;
    candidate.sequence = localMessages[i].sequence;
    candidate.timestamp = localMessages[i].timestamp;
    memcpy(candidate.packetId, localMessages[i].packetId, 16);
  }

  xSemaphoreGive(protocolStateMutex);

  if (candidateCount == 0)
  {
    Serial.println("REQUEST_SYNC response: no cached local MESSAGE");
    return;
  }

  uint8_t missingMask = 0;
  for (uint8_t i = 0; i < candidateCount; i++)
  {
    const Candidate& candidate = candidates[i];

    Serial.print("Local MESSAGE packet ID: ");
    printHex(candidate.packetId, 16);
    Serial.println();

    if (
      now >= PUBLIC_MESSAGE_MAX_AGE_MS &&
      candidate.timestamp < now - PUBLIC_MESSAGE_MAX_AGE_MS
    )
    {
      Serial.println("REQUEST_SYNC MESSAGE: skipped (stale)");
      continue;
    }

    if (
      request.hasSinceTimestamp &&
      candidate.timestamp < request.sinceTimestamp
    )
    {
      Serial.println("REQUEST_SYNC MESSAGE: skipped (before since cursor)");
      continue;
    }

    bool present = gcsFilterMightContain(request, candidate.packetId);
    Serial.print("GCS membership: ");
    Serial.println(present ? "PRESENT" : "MISSING");
    if (present)
    {
      continue;
    }

    if (!reserveRequestSyncResponse())
    {
      Serial.println("REQUEST_SYNC MESSAGE response: RATE LIMITED");
      break;
    }

    missingMask |= 1 << i;
  }

  if (missingMask == 0)
  {
    Serial.println("REQUEST_SYNC MESSAGE response: not needed");
    return;
  }

  if (!takeProtocolStateMutex())
  {
    Serial.println("REQUEST_SYNC MESSAGE: LOCK TIMEOUT");
    return;
  }

  uint8_t queued = 0;
  for (uint8_t i = 0; i < candidateCount; i++)
  {
    const Candidate& candidate = candidates[i];
    // Skip a slot that was replaced by a newer message during evaluation.
    if (
      (missingMask & (1 << i)) == 0 ||
      localMessages[candidate.slot].sequence != candidate.sequence
    )
    {
      continue;
    }

    localMessageResponsePendingMask |= 1 << candidate.slot;
    queued++;
  }

  xSemaphoreGive(protocolStateMutex);

  Serial.print("REQUEST_SYNC MESSAGE response: ");
  Serial.print(queued);
  Serial.println(" RSR MESSAGE QUEUED");
}

void serviceLocalMessageResponses()
{
  if (!bitchatLinkReady)
  {
    return;
  }

  static uint8_t packet[MAX_LOCAL_MESSAGE_PACKET];
  size_t packetLength = 0;

  if (!takeProtocolStateMutex())
  {
    return;
  }

  for (uint8_t i = 0; i < LOCAL_MESSAGE_CACHE_SIZE; i++)
  {
    if ((localMessageResponsePendingMask & (1 << i)) == 0)
    {
      continue;
    }

    localMessageResponsePendingMask &= ~(1 << i);
    if (localMessages[i].used)
    {
      packetLength = localMessages[i].packetLength;
      memcpy(packet, localMessages[i].packet, packetLength);
    }
    break;
  }

  xSemaphoreGive(protocolStateMutex);

  if (packetLength == 0)
  {
    return;
  }

  // TTL and RSR are mutable relay fields and are excluded from the signature.
  packet[2] = 0;
  packet[11] |= 0x10;

  Serial.println();
  Serial.println("=== REQUEST_SYNC MESSAGE RESPONSE TX ===");
  Serial.print("Timestamp (ms): ");
  printUInt64(readBE64(packet + 3));
  Serial.println();
  Serial.println("TTL: 0");
  Serial.println("Flags: 0x12 [signature, RSR]");
  transmitBitchatPacket(packet, packetLength);
}

// Each line typed in the serial monitor is sent as one public message. The
// monitor must be configured to send a newline or carriage return.
void serviceSerialInput()
{
  static uint8_t line[MAX_LOCAL_MESSAGE_BYTES];
  static size_t lineLength = 0;
  static bool lineOverflow = false;

  while (Serial.available() > 0)
  {
    int value = Serial.read();
    if (value < 0)
    {
      break;
    }

    if (value == '\r' || value == '\n')
    {
      if (lineOverflow)
      {
        Serial.print("Serial input: REJECTED (exceeds ");
        Serial.print(MAX_LOCAL_MESSAGE_BYTES);
        Serial.println(" bytes)");
      }
      else if (lineLength > 0)
      {
        if (isValidUtf8(line, lineLength))
        {
          sendLocalPublicMessage(line, lineLength);
        }
        else
        {
          Serial.println("Serial input: REJECTED (invalid UTF-8)");
        }
      }

      lineLength = 0;
      lineOverflow = false;
      continue;
    }

    if (lineOverflow)
    {
      continue;
    }

    if (lineLength >= sizeof(line))
    {
      lineOverflow = true;
      continue;
    }

    line[lineLength++] = (uint8_t)value;
  }
}

bool parseAnnouncePayload(
  const uint8_t* payload,
  size_t payloadLength,
  uint8_t* noisePublicKey,
  uint8_t* signingPublicKey,
  uint8_t* nickname,
  uint8_t* nicknameLength
)
{
  bool hasNickname = false;
  bool hasNoisePublicKey = false;
  bool hasSigningPublicKey = false;
  size_t offset = 0;

  memset(noisePublicKey, 0, 32);
  memset(signingPublicKey, 0, 32);
  *nicknameLength = 0;

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
        // A one-byte TLV length always fits MAX_NICKNAME_BYTES.
        memcpy(nickname, value, tlvLength);
        *nicknameLength = tlvLength;
        hasNickname = true;
        break;

      case 0x02:
        Serial.print("Noise public key (X25519) [");
        Serial.print(tlvLength);
        Serial.print(" bytes]: ");
        printHex(value, tlvLength);
        Serial.println();
        hasNoisePublicKey = tlvLength == 32;
        if (hasNoisePublicKey)
        {
          memcpy(noisePublicKey, value, 32);
        }
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
  const uint8_t* recipientId = NULL;

  if (flags & 0x01)
  {
    // A directed packet includes an 8-byte recipient ID.
    if (payloadOffset + 8 > len)
    {
      Serial.println("Recipient ID is incomplete");
      return;
    }

    recipientId = data + payloadOffset;
    Serial.print("Recipient ID: ");
    printHex(recipientId, 8);
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
  uint8_t announceNoisePublicKey[32];
  uint8_t announceSigningPublicKey[32];
  static uint8_t announceNickname[MAX_NICKNAME_BYTES];
  uint8_t announceNicknameLength = 0;
  bool announceFieldsValid = false;
  bool announceIdentityValid = false;

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
      senderId,
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
      announceNoisePublicKey,
      announceSigningPublicKey,
      announceNickname,
      &announceNicknameLength
    );

    if (announceFieldsValid)
    {
      announceIdentityValid = verifyNoiseKeySenderId(
        senderId,
        announceNoisePublicKey
      );
    }
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
      bool signatureValid = verifyBitchatSignature(
        data,
        signatureOffset,
        signature,
        announceSigningPublicKey
      );

      uint64_t announceTimestamp = readBE64(data + 3);
      uint64_t now = 0;
      bool stale =
        currentEpochMilliseconds(&now) &&
        now >= ANNOUNCE_MAX_AGE_MS &&
        announceTimestamp < now - ANNOUNCE_MAX_AGE_MS;

      if (signatureValid && announceIdentityValid && stale)
      {
        Serial.println("ANNOUNCE rejected: stale (older than 15 minutes)");
      }
      else if (
        signatureValid &&
        announceIdentityValid &&
        rememberVerifiedPeer(
          senderId,
          announceSigningPublicKey,
          announceNickname,
          announceNicknameLength
        ) <= VERIFIED_PEER_REFRESHED &&
        ttl == DIRECT_ANNOUNCE_TTL
      )
      {
        // Only a peer's own, unrelayed announcement sets the clock and
        // prompts a local announcement in reply.
        synchronizeClock(announceTimestamp);
        requestLocalAnnounce();
      }
    }
  }
  else if (type == 0x02)
  {
    handlePublicMessagePacket(
      data,
      signatureOffset,
      signature,
      ttl,
      flags,
      senderId,
      recipientId,
      payload,
      payloadLength
    );
  }
  else if (type == 0x21)
  {
    if (flags & 0x04)
    {
      Serial.println("REQUEST_SYNC rejected: compressed payload unsupported");
    }
    else
    {
      handleRequestSyncPacket(
        data,
        signatureOffset,
        signature,
        ttl,
        senderId,
        recipientId,
        payload,
        payloadLength
      );
    }
  }
}

void resetFragmentAssembly(FragmentAssembly& assembly)
{
  memset(&assembly, 0, sizeof(assembly));
}

// Returns the assembly for this sender and fragment ID, or starts one in a
// free, expired, or (when all are busy) the oldest slot.
FragmentAssembly& selectFragmentAssembly(
  const uint8_t* senderId,
  const uint8_t* fragmentId,
  bool* isNew
)
{
  FragmentAssembly* candidate = &fragmentAssemblies[0];
  bool candidateFree = false;

  for (uint8_t i = 0; i < FRAGMENT_ASSEMBLY_SLOTS; i++)
  {
    FragmentAssembly& assembly = fragmentAssemblies[i];

    // Discard an assembly that has been inactive for more than 30 seconds.
    if (assembly.active && millis() - assembly.startedAt > 30000)
    {
      Serial.println("Fragment assembly timeout");
      resetFragmentAssembly(assembly);
    }

    if (
      assembly.active &&
      memcmp(assembly.senderId, senderId, 8) == 0 &&
      memcmp(assembly.id, fragmentId, 8) == 0
    )
    {
      *isNew = false;
      return assembly;
    }

    if (candidateFree)
    {
      continue;
    }

    if (!assembly.active)
    {
      candidate = &assembly;
      candidateFree = true;
    }
    else if (
      (uint32_t)(millis() - assembly.startedAt) >
      (uint32_t)(millis() - candidate->startedAt)
    )
    {
      candidate = &assembly;
    }
  }

  if (!candidateFree)
  {
    Serial.print("Fragment assembly evicted: ");
    printHex(candidate->id, 8);
    Serial.println();
  }

  *isNew = true;
  return *candidate;
}

void handle_fragment(
  const uint8_t* senderId,
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

  if (originalType == 0x20)
  {
    Serial.println("Nested fragment rejected");
    return;
  }

  bool isNewAssembly = false;
  FragmentAssembly& fragmentAssembly = selectFragmentAssembly(
    senderId,
    fragmentId,
    &isNewAssembly
  );

  // Start a new fragment ID.
  if (isNewAssembly)
  {
    resetFragmentAssembly(fragmentAssembly);

    fragmentAssembly.active = true;

    memcpy(fragmentAssembly.senderId, senderId, 8);
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
    resetFragmentAssembly(fragmentAssembly);
    return;
  }

  if (fragmentAssembly.originalType != originalType)
  {
    Serial.println("Fragment original type mismatch");
    resetFragmentAssembly(fragmentAssembly);
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
      resetFragmentAssembly(fragmentAssembly);
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
    resetFragmentAssembly(fragmentAssembly);
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
  resetFragmentAssembly(fragmentAssembly);

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

  identityFileSystemReady = InternalFS.begin();
  Serial.print("Identity filesystem: ");
  Serial.println(identityFileSystemReady ? "READY" : "FAILED");

  cryptoReady = nRFCrypto.begin();
  Serial.print("Ed25519 verifier: ");
  Serial.println(cryptoReady ? "READY" : "FAILED");

  if (cryptoReady)
  {
    cryptoMutex = xSemaphoreCreateMutex();
    if (cryptoMutex == NULL)
    {
      Serial.println("CryptoCell mutex: FAILED");
      cryptoReady = false;
    }
  }

  protocolStateMutex = xSemaphoreCreateMutex();
  Serial.print("Protocol state mutex: ");
  Serial.println(protocolStateMutex != NULL ? "READY" : "FAILED");

  if (!initializeLocalIdentity())
  {
    Serial.println("Local Bitchat identity: FAILED");
  }

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
  Serial.println("Type a line and press Enter to send a public message.");

#if FORCE_REQUEST_SYNC_MISSING_TEST
  Serial.println(
    "WARNING: REQUEST_SYNC forced-missing one-shot test is ENABLED"
  );
#endif

  Bluefruit.Scanner.start(0);
}


void loop()
{
  serviceSerialInput();
  serviceRequestSyncResponse();
  serviceLocalMessageResponses();
  serviceLocalAnnounce();
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

  bitchatCharacteristicProperties = bitchatChar.properties();
  Serial.print("Characteristic properties: 0x");
  if (bitchatCharacteristicProperties < 0x10) Serial.print('0');
  Serial.println(bitchatCharacteristicProperties, HEX);

  if (
    !(bitchatCharacteristicProperties & CHR_PROPS_WRITE_WO_RESP) &&
    !(bitchatCharacteristicProperties & CHR_PROPS_WRITE)
  )
  {
    Serial.println("Characteristic is not writable");
    Bluefruit.disconnect(conn_handle);
    return;
  }

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
    bitchatLinkMtu = connection->getMtu();
    Serial.print("MTU after exchange: ");
    Serial.println(bitchatLinkMtu);
  }

  bitchatLinkReady = true;
  localAnnouncePending = true;
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

  bitchatLinkReady = false;
  bitchatCharacteristicProperties = 0;
  bitchatLinkMtu = 23;
  localAnnouncePending = false;
  requestSyncResponsePending = false;
  requestSyncResponseWindowStartedAt = 0;
  requestSyncResponseCount = 0;

  if (takeProtocolStateMutex())
  {
    localMessageResponsePendingMask = 0;
    xSemaphoreGive(protocolStateMutex);
  }

  connecting = false;

  Serial.println("Scanning again...");
}
