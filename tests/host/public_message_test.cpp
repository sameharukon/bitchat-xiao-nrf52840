#include "../../sketch_bitchat.ino"
#include <cassert>
#include <iostream>

uint32_t g_millis = 1000;
SerialStub Serial;
nRFCryptoClass nRFCrypto;
InternalFSClass InternalFS;
BluefruitStub Bluefruit;

static EVP_PKEY* edFromSeed(const uint8_t* seed) { return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed, 32); }

CRYSError_t CRYS_ECEDW_Verify(const uint8_t* sig, size_t, const uint8_t* pub, size_t, uint8_t* msg, size_t len, CRYS_ECEDW_TempBuff_t*) {
  EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub, 32);
  EVP_MD_CTX* c = EVP_MD_CTX_new(); EVP_DigestVerifyInit(c, nullptr, nullptr, nullptr, k);
  int r = EVP_DigestVerify(c, sig, 64, msg, len); EVP_MD_CTX_free(c); EVP_PKEY_free(k);
  return r == 1 ? CRYS_OK : 0x1234; }
CRYSError_t CRYS_ECEDW_Sign(uint8_t* sig, size_t* sl, const uint8_t* msg, size_t len, const uint8_t* sk, size_t, CRYS_ECEDW_TempBuff_t*) {
  EVP_PKEY* k = edFromSeed(sk); EVP_MD_CTX* c = EVP_MD_CTX_new(); EVP_DigestSignInit(c, nullptr, nullptr, nullptr, k);
  int r = EVP_DigestSign(c, sig, sl, msg, len); EVP_MD_CTX_free(c); EVP_PKEY_free(k); return r == 1 ? CRYS_OK : 1; }
CRYSError_t CRYS_ECEDW_SeedKeyPair(const uint8_t* seed, size_t, uint8_t* sk, size_t* skl, uint8_t* pk, size_t* pkl, CRYS_ECEDW_TempBuff_t*) {
  EVP_PKEY* k = edFromSeed(seed); size_t l = 32; EVP_PKEY_get_raw_public_key(k, pk, &l); EVP_PKEY_free(k);
  memcpy(sk, seed, 32); memcpy(sk + 32, pk, 32); *skl = 64; *pkl = 32; return CRYS_OK; }
CRYSError_t CRYS_ECMONT_SeedKeyPair(uint8_t* pk, size_t* pkl, uint8_t* sk, size_t* skl, const uint8_t* seed, size_t, CRYS_ECMONT_TempBuff_t*) {
  EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, seed, 32); size_t l = 32;
  EVP_PKEY_get_raw_public_key(k, pk, &l); EVP_PKEY_free(k); memcpy(sk, seed, 32); *pkl = 32; *skl = 32; return CRYS_OK; }

typedef std::vector<uint8_t> Bytes;
static Bytes sha(const Bytes& d) { Bytes o(32); unsigned l; EVP_Digest(d.data(), d.size(), o.data(), &l, EVP_sha256(), nullptr); return o; }
static void be64(Bytes& b, uint64_t v) { for (int i = 7; i >= 0; i--) b.push_back((uint8_t)(v >> (i * 8))); }

struct Peer { uint8_t edSeed[32]; uint8_t edPub[32]; uint8_t xPub[32]; uint8_t id[8]; };
static Peer makePeer(uint8_t s) {
  Peer p; for (int i = 0; i < 32; i++) p.edSeed[i] = s + i;
  EVP_PKEY* k = edFromSeed(p.edSeed); size_t l = 32; EVP_PKEY_get_raw_public_key(k, p.edPub, &l); EVP_PKEY_free(k);
  uint8_t xs[32]; for (int i = 0; i < 32; i++) xs[i] = s * 3 + i;
  k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, xs, 32); l = 32; EVP_PKEY_get_raw_public_key(k, p.xPub, &l); EVP_PKEY_free(k);
  Bytes h = sha(Bytes(p.xPub, p.xPub + 32)); memcpy(p.id, h.data(), 8); return p; }

// Independent canonical signing implementation.
static Bytes signPacket(const Peer& p, Bytes pkt) {
  Bytes c = pkt; c[2] = 0; c[11] &= (0x01 | 0x04);
  size_t buckets[] = {256, 512, 1024, 2048};
  for (size_t b : buckets) if (c.size() + 16 <= b) { size_t pad = b - c.size(); if (pad <= 255) c.insert(c.end(), pad, (uint8_t)pad); break; }
  EVP_PKEY* k = edFromSeed(p.edSeed); EVP_MD_CTX* x = EVP_MD_CTX_new(); EVP_DigestSignInit(x, nullptr, nullptr, nullptr, k);
  uint8_t sig[64]; size_t sl = 64; EVP_DigestSign(x, sig, &sl, c.data(), c.size()); EVP_MD_CTX_free(x); EVP_PKEY_free(k);
  pkt.insert(pkt.end(), sig, sig + 64); return pkt; }

static Bytes packet(uint8_t type, uint8_t ttl, uint64_t ts, uint8_t flags, const uint8_t* sender, const uint8_t* recipient, const Bytes& payload) {
  Bytes b = {1, type, ttl}; be64(b, ts); b.push_back(flags); b.push_back(payload.size() >> 8); b.push_back(payload.size() & 0xFF);
  b.insert(b.end(), sender, sender + 8); if (recipient) b.insert(b.end(), recipient, recipient + 8);
  b.insert(b.end(), payload.begin(), payload.end()); return b; }

static void tlv(Bytes& b, uint8_t t, const uint8_t* v, size_t n) { b.push_back(t); b.push_back(n); b.insert(b.end(), v, v + n); }

static std::string feed(const Bytes& b) { Serial.out.clear(); parse_bitchat_packet(b.data(), b.size()); return Serial.out; }
static bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }
static int count(const std::string& s, const char* n) { int c = 0; for (size_t p = 0; (p = s.find(n, p)) != std::string::npos; p++) c++; return c; }
static int failures = 0;
#define CHECK(cond, name) do { bool ok_ = (cond); std::cout << (ok_ ? "PASS " : "FAIL ") << name << "\n"; if (!ok_) { failures++; std::cout << out << "\n"; } } while (0)

static Bytes msg(const Peer& p, uint64_t ts, const std::string& text, uint8_t ttl = 7, const uint8_t* rcpt = nullptr) {
  return signPacket(p, packet(0x02, ttl, ts, 0x02 | (rcpt ? 0x01 : 0), p.id, rcpt, Bytes(text.begin(), text.end()))); }

int main() {
  setup();
  std::string out = Serial.out;
  CHECK(has(out, "Local identity storage: CREATED"), "identity created");

  const uint64_t T0 = 1786423285123ULL;  // 2026-08-11T04:41:25.123Z
  Peer peer = makePeer(7);
  Bytes ann;
  const char* nick = "anon8168";
  tlv(ann, 1, (const uint8_t*)nick, strlen(nick)); tlv(ann, 2, peer.xPub, 32); tlv(ann, 3, peer.edPub, 32);
  uint8_t caps[2] = {0x29, 0x03}; tlv(ann, 5, caps, 2);

  // A message before any announcement must be rejected.
  out = feed(msg(peer, T0, "early"));
  CHECK(has(out, "sender has no verified ANNOUNCE") && !has(out, "Content:"), "unknown sender rejected");

  connect_callback(0);
  out = feed(signPacket(peer, packet(0x01, 7, T0, 0x02, peer.id, nullptr, ann)));
  CHECK(has(out, "Sender ID verification: VALID") && has(out, "Verified peer cache: UPDATED"), "announce verified");
  loop();

  out = feed(msg(peer, T0 + 1000, "hello xiao"));
  CHECK(has(out, "--- PUBLIC MESSAGE ---") && has(out, "Sender: anon8168") && has(out, "Content: hello xiao\n")
        && has(out, "(2026-08-11T04:41:26.123Z)") && has(out, "Signature verification: VALID"), "ASCII message displayed");

  out = feed(msg(peer, T0 + 1000, "hello xiao", 3));
  CHECK(has(out, "duplicate packet ID") && !has(out, "Content:"), "duplicate (relayed TTL) suppressed");

  out = feed(msg(peer, T0 + 2000, "こんにちは 🌸 XIAO"));
  CHECK(has(out, "Content: こんにちは 🌸 XIAO\n"), "Japanese and emoji displayed intact");

  Bytes bad = msg(peer, T0 + 3000, "tampered"); bad[bad.size() - 1] ^= 1;
  out = feed(bad);
  CHECK(has(out, "signature verification failed") && !has(out, "Content:"), "invalid signature rejected");
  out = feed(msg(peer, T0 + 3000, "tampered"));
  CHECK(has(out, "Content: tampered"), "forged copy did not poison duplicate ring");

  Bytes alteredText = msg(peer, T0 + 3500, "original"); alteredText[22] = 'O';
  out = feed(alteredText);
  CHECK(has(out, "signature verification failed") && !has(out, "Content:"), "altered content rejected");

  out = feed(packet(0x02, 7, T0 + 4000, 0x00, peer.id, nullptr, Bytes{'h','i'}));
  CHECK(has(out, "signature is missing") && !has(out, "Content:"), "missing signature rejected");

  out = feed(msg(peer, T0 - 7ULL * 3600 * 1000, "old news"));
  CHECK(has(out, "stale broadcast") && !has(out, "Content:"), "message older than six hours rejected");
  out = feed(msg(peer, T0 - 5ULL * 3600 * 1000, "recent history"));
  CHECK(has(out, "Content: recent history"), "message within six hours accepted");

  Bytes invalidUtf8 = signPacket(peer, packet(0x02, 7, T0 + 5000, 0x02, peer.id, nullptr, Bytes{'a', 0xC0, 0xAF}));
  out = feed(invalidUtf8);
  CHECK(has(out, "not valid UTF-8") && !has(out, "Content:"), "invalid UTF-8 rejected");

  out = feed(msg(peer, T0 + 6000, "a\x1b[2Jb\xe2\x80\xae" "c\\d"));
  CHECK(has(out, "Content: a\\x1B[2Jb\\u{202E}c\\\\d\n"), "control and bidi characters escaped");

  Bytes compressed = msg(peer, T0 + 6500, "zz"); compressed[11] |= 0x04;
  out = feed(compressed);
  CHECK(has(out, "compressed payload unsupported") && !has(out, "Content:"), "compressed rejected");

  uint8_t other[8] = {1,2,3,4,5,6,7,8};
  out = feed(msg(peer, T0 + 7000, "not for you", 7, other));
  CHECK(has(out, "addressed to another peer") && !has(out, "Content:"), "message for another peer rejected");
  uint8_t bcast[8]; memset(bcast, 0xFF, 8);
  out = feed(msg(peer, T0 + 7100, "explicit broadcast", 7, bcast));
  CHECK(has(out, "--- PUBLIC MESSAGE ---") && has(out, "Content: explicit broadcast"), "explicit broadcast recipient accepted");

  Peer impostor = makePeer(9); memcpy(impostor.id, peer.id, 8);
  out = feed(msg(impostor, T0 + 8000, "spoofed"));
  CHECK(has(out, "signature verification failed") && !has(out, "Content:"), "spoofed sender ID rejected");

  out = feed(signPacket(peer, packet(0x02, 7, T0 + 8500, 0x02, localIdentity.senderId, nullptr, Bytes{'x'})));
  CHECK(has(out, "self echo") && !has(out, "Content:"), "self echo rejected");

  // Long fragmented message.
  std::string longText; for (int i = 0; i < 40; i++) longText += "長いメッセージ" + std::to_string(i) + " ";
  Bytes inner = msg(peer, T0 + 9000, longText);
  uint8_t fid[8] = {9,9,9,9,1,2,3,4}; size_t chunk = 400; uint16_t total = (inner.size() + chunk - 1) / chunk;
  std::string all;
  for (uint16_t i = 0; i < total; i++) {
    Bytes fp(fid, fid + 8); fp.push_back(i >> 8); fp.push_back(i & 0xFF); fp.push_back(total >> 8); fp.push_back(total & 0xFF); fp.push_back(0x02);
    size_t e = std::min(inner.size(), (size_t)(i + 1) * chunk); fp.insert(fp.end(), inner.begin() + i * chunk, inner.begin() + e);
    all += feed(packet(0x20, 7, T0 + 9000, 0x00, peer.id, nullptr, fp));
  }
  out = all;
  CHECK(total > 1 && has(out, "FRAGMENT REASSEMBLY COMPLETE") && count(out, "Content: ") == 1 && has(out, ("Content: " + longText + "\n").c_str()),
        "fragmented long message displayed once");

  // Packet ID refactor matches the official definition for the cached local announce.
  uint8_t cached[MAX_ANNOUNCE_PACKET]; size_t cl = 0;
  bool haveCached = getCachedLocalAnnouncePacket(cached, &cl);
  uint8_t id[16]; bool idOk = haveCached && calculatePacketId(cached, cl, id);
  Bytes idIn; idIn.push_back(cached[1]); idIn.insert(idIn.end(), cached + 14, cached + 22); idIn.insert(idIn.end(), cached + 3, cached + 11);
  idIn.insert(idIn.end(), cached + 22, cached + 22 + readBE16(cached + 12));
  out = "";
  CHECK(idOk && memcmp(sha(idIn).data(), id, 16) == 0, "local ANNOUNCE packet ID unchanged by refactor");

  disconnect_callback(0, 0x13);
  out = feed(msg(peer, T0 + 10000, "after disconnect"));
  CHECK(has(out, "sender has no verified ANNOUNCE"), "peer cache cleared on disconnect");

  std::cout << (failures ? "FAILURES: " : "ALL PASSED ") << failures << "\n";
  return failures ? 1 : 0;
}
