#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <string>
#include <map>
#include <vector>
#include <openssl/evp.h>

#define HEX 16
#define DEC 10
extern uint32_t g_millis;
inline uint32_t millis() { return g_millis; }
inline void delay(uint32_t ms) { g_millis += ms; }

struct SerialStub {
  std::string out;
  explicit operator bool() const { return true; }
  void begin(int) {}
  size_t write(uint8_t c) { out.push_back((char)c); return 1; }
  size_t write(const uint8_t* d, size_t n) { out.append((const char*)d, n); return n; }
  void print(const char* s) { out += s; }
  void print(char c) { out.push_back(c); }
  void print(const std::string& s) { out += s; }
  void printNum(unsigned long long v, int base) {
    char b[32]; snprintf(b, sizeof b, base == 16 ? "%llX" : "%llu", v); out += b; }
  void print(unsigned char v, int base = DEC) { printNum(v, base); }
  void print(int v, int base = DEC) { if (base==DEC && v<0) { out+="-"; v=-v; } printNum((unsigned)v, base); }
  void print(unsigned int v, int base = DEC) { printNum(v, base); }
  void print(long v, int base = DEC) { if (base==DEC && v<0) { out+="-"; v=-v; } printNum((unsigned long)v, base); }
  void print(unsigned long v, int base = DEC) { printNum(v, base); }
  template <typename T> void println(T v) { print(v); out += "\n"; }
  template <typename T> void println(T v, int base) { print(v, base); out += "\n"; }
  void println() { out += "\n"; }
  void printBufferReverse(const uint8_t*, int, char) {}
};
extern SerialStub Serial;

// FreeRTOS
typedef void* SemaphoreHandle_t;
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
inline SemaphoreHandle_t xSemaphoreCreateMutex() { static int m; return &m; }
inline int xSemaphoreTake(SemaphoreHandle_t, int) { return pdTRUE; }
inline int xSemaphoreGive(SemaphoreHandle_t) { return pdTRUE; }

// CryptoCell
typedef uint32_t CRYSError_t;
#define CRYS_OK 0
typedef struct { uint8_t b[16]; } CRYS_ECEDW_TempBuff_t;
typedef struct { uint8_t b[16]; } CRYS_ECMONT_TempBuff_t;
#define CRYS_HASH_SHA256_mode 2
CRYSError_t CRYS_ECEDW_Verify(const uint8_t* sig, size_t sigLen, const uint8_t* pub, size_t pubLen,
  uint8_t* msg, size_t msgLen, CRYS_ECEDW_TempBuff_t*);
CRYSError_t CRYS_ECEDW_Sign(uint8_t* sig, size_t* sigLen, const uint8_t* msg, size_t msgLen,
  const uint8_t* sk, size_t skLen, CRYS_ECEDW_TempBuff_t*);
CRYSError_t CRYS_ECEDW_SeedKeyPair(const uint8_t* seed, size_t seedLen, uint8_t* sk, size_t* skLen,
  uint8_t* pk, size_t* pkLen, CRYS_ECEDW_TempBuff_t*);
CRYSError_t CRYS_ECMONT_SeedKeyPair(uint8_t* pk, size_t* pkLen, uint8_t* sk, size_t* skLen,
  const uint8_t* seed, size_t seedLen, CRYS_ECMONT_TempBuff_t*);

struct nRFCryptoClass { bool begin() { return true; } };
extern nRFCryptoClass nRFCrypto;
struct nRFCrypto_Hash {
  EVP_MD_CTX* ctx = nullptr;
  bool begin(int) { if (!ctx) ctx = EVP_MD_CTX_new(); return EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1; }
  bool update(uint8_t* d, size_t n) { return EVP_DigestUpdate(ctx, d, n) == 1; }
  uint8_t end(uint8_t* out) { unsigned l = 0; EVP_DigestFinal_ex(ctx, out, &l); return (uint8_t)l; }
};
struct nRFCrypto_Random {
  bool begin() { return true; }
  void end() {}
  bool generate(uint8_t* b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(rand()); return true; }
};

// LittleFS
#define FILE_O_READ 0
#define FILE_O_WRITE 1
struct InternalFSClass {
  std::map<std::string, std::vector<uint8_t>> files;
  bool begin() { return true; }
  bool exists(const char* p) { return files.count(p) > 0; }
  bool remove(const char* p) { return files.erase(p) > 0; }
  bool rename(const char* a, const char* b) { if (!exists(a)) return false; files[b] = files[a]; files.erase(a); return true; }
};
extern InternalFSClass InternalFS;
namespace Adafruit_LittleFS_Namespace {
struct File {
  InternalFSClass& fs; std::string path; size_t pos = 0; bool isOpen = false;
  explicit File(InternalFSClass& f) : fs(f) {}
  bool open(const char* p, int mode) {
    path = p; pos = 0;
    if (mode == FILE_O_READ) { if (!fs.exists(p)) return false; }
    else fs.files[p];
    isOpen = true; return true; }
  size_t size() { return fs.files[path].size(); }
  int32_t read(uint8_t* b, size_t n) { auto& v = fs.files[path]; size_t c = std::min(n, v.size() - pos); memcpy(b, v.data() + pos, c); pos += c; return (int32_t)c; }
  size_t write(const uint8_t* b, size_t n) { auto& v = fs.files[path]; v.insert(v.end(), b, b + n); return n; }
  void flush() {}
  void close() { isOpen = false; }
};
}

// Bluefruit
#define CHR_PROPS_WRITE_WO_RESP 0x04
#define CHR_PROPS_WRITE 0x08
#define BANDWIDTH_MAX 3
struct BLEUuid { BLEUuid(const char*) {} };
struct BLEClientCharacteristic;
typedef void (*notify_cb_t)(BLEClientCharacteristic*, uint8_t*, uint16_t);
struct BLEClientCharacteristic {
  std::vector<std::vector<uint8_t>> writes;
  explicit BLEClientCharacteristic(BLEUuid) {}
  void setNotifyCallback(notify_cb_t) {}
  void begin() {}
  bool discover() { return true; }
  uint8_t properties() { return CHR_PROPS_WRITE_WO_RESP; }
  bool enableNotify() { return true; }
  uint16_t write(const void* d, uint16_t n) { writes.emplace_back((const uint8_t*)d, (const uint8_t*)d + n); return n; }
  uint16_t write_resp(const void* d, uint16_t n) { return write(d, n); }
};
struct BLEClientService { explicit BLEClientService(BLEUuid) {} void begin() {} bool discover(uint16_t) { return true; } };
struct BLEConnection { uint16_t getMtu() { return 247; } bool requestMtuExchange(uint16_t) { return true; } };
struct ble_data_t { uint8_t* p_data; uint16_t len; };
struct ble_gap_addr_t { uint8_t addr[6]; };
struct ble_gap_evt_adv_report_t { ble_data_t data; ble_gap_addr_t peer_addr; int8_t rssi; };
typedef void (*conn_cb_t)(uint16_t);
typedef void (*disc_cb_t)(uint16_t, uint8_t);
typedef void (*scan_cb_t)(ble_gap_evt_adv_report_t*);
struct CentralStub { bool connect(ble_gap_evt_adv_report_t*) { return true; } void setConnectCallback(conn_cb_t) {} void setDisconnectCallback(disc_cb_t) {} };
struct ScannerStub { void setRxCallback(scan_cb_t) {} void restartOnDisconnect(bool) {} void setInterval(int,int) {} void useActiveScan(bool) {} void start(int) {} void resume() {} };
struct BluefruitStub {
  CentralStub Central; ScannerStub Scanner; BLEConnection conn;
  void configCentralBandwidth(int) {} void configPrphBandwidth(int) {} void begin(int,int) {}
  void setName(const char*) {} void disconnect(uint16_t) {}
  BLEConnection* Connection(uint16_t) { return &conn; }
};
extern BluefruitStub Bluefruit;
