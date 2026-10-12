#include "../../sketch_bitchat.ino"
#include <cassert>
#include <iostream>
#include <algorithm>

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


static bool verifyLocal(const Bytes& pkt) {
  // Independent canonical verification with the local signing key.
  if (pkt.size() < 86) return false;
  Bytes c(pkt.begin(), pkt.end() - 64); c[2] = 0; c[11] &= (0x01 | 0x04);
  size_t buckets[] = {256, 512, 1024, 2048};
  for (size_t b : buckets) if (c.size() + 16 <= b) { size_t pad = b - c.size(); if (pad <= 255) c.insert(c.end(), pad, (uint8_t)pad); break; }
  EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, localIdentity.signingPublicKey, 32);
  EVP_MD_CTX* x = EVP_MD_CTX_new(); EVP_DigestVerifyInit(x, nullptr, nullptr, nullptr, k);
  int r = EVP_DigestVerify(x, pkt.data() + pkt.size() - 64, 64, c.data(), c.size());
  EVP_MD_CTX_free(x); EVP_PKEY_free(k); return r == 1; }

// Reassembles the fragments written by the XIAO, checking each frame.
static bool reassembleWrites(const std::vector<Bytes>& writes, Bytes& outPkt, uint8_t expectTtl, uint8_t expectFlags) {
  if (writes.empty()) return false;
  uint16_t total = 0; Bytes id;
  for (size_t i = 0; i < writes.size(); i++) {
    const Bytes& w = writes[i];
    if (w.size() > 244 || w[0] != 1 || w[1] != 0x20 || w[2] != expectTtl || w[11] != expectFlags) return false;
    if (readBE16(&w[12]) + 22u != w.size() || memcmp(&w[14], localIdentity.senderId, 8) != 0) return false;
    Bytes fid(w.begin() + 22, w.begin() + 30);
    if (i == 0) { id = fid; total = readBE16(&w[32]); } else if (fid != id || readBE16(&w[32]) != total) return false;
    if (readBE16(&w[30]) != i || w[34] != 0x02) return false;
    outPkt.insert(outPkt.end(), w.begin() + 35, w.end());
  }
  return total == writes.size(); }

static void tlv16(Bytes& b, uint8_t t, const Bytes& v) { b.push_back(t); b.push_back(v.size() >> 8); b.push_back(v.size() & 0xFF); b.insert(b.end(), v.begin(), v.end()); }

// Golomb-Rice set containing the given packet IDs, matching the firmware decoder.
static Bytes gcsEncode(std::vector<Bytes> ids, uint8_t p, uint32_t m) {
  std::vector<uint64_t> buckets;
  for (auto& id : ids) { Bytes h = sha(id); uint64_t v = readBE64(h.data()) & 0x7FFFFFFFFFFFFFFFULL; v %= m; if (v == 0) v = 1; buckets.push_back(v); }
  std::sort(buckets.begin(), buckets.end());
  std::vector<int> bits; uint64_t prev = 0;
  for (uint64_t b : buckets) { uint64_t d = b - prev - 1; prev = b; for (uint64_t q = d >> p; q > 0; q--) bits.push_back(1); bits.push_back(0);
    for (int i = p - 1; i >= 0; i--) bits.push_back((d >> i) & 1); }
  Bytes out((bits.size() + 7) / 8, 0);
  for (size_t i = 0; i < bits.size(); i++) if (bits[i]) out[i / 8] |= 0x80 >> (i % 8);
  return out; }

static Bytes requestSync(const Peer& p, uint64_t ts, const Bytes& gcs, uint16_t types, const uint64_t* since = nullptr) {
  Bytes pl; tlv16(pl, 1, Bytes{7}); tlv16(pl, 2, Bytes{0, 0, 0x10, 0}); tlv16(pl, 3, gcs);
  tlv16(pl, 4, Bytes{(uint8_t)types, (uint8_t)(types >> 8)});
  if (since) { Bytes v; be64(v, *since); tlv16(pl, 5, v); }
  return signPacket(p, packet(0x21, 0, ts, 0x03, p.id, localIdentity.senderId, pl)); }

static std::string typeLine(const std::string& line) { Serial.out.clear(); Serial.in = line; serviceSerialInput(); return Serial.out; }

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


  // ---- Local public message transmission ----
  bitchatChar.writes.clear();
  out = typeLine("hello iphone\n");
  CHECK(bitchatChar.writes.size() == 1 && has(out, "Local MESSAGE signature self-check: VALID")
        && has(out, "Content: hello iphone\n"), "short message sent in one write");
  Bytes sent = bitchatChar.writes.empty() ? Bytes() : bitchatChar.writes[0];
  const std::string shortText = "hello iphone";
  Bytes expectedShort(shortText.begin(), shortText.end());
  CHECK(sent.size() == 22 + 12 + 64 && sent[0] == 1 && sent[1] == 0x02 && sent[2] == 7 && sent[11] == 0x02
        && memcmp(&sent[14], localIdentity.senderId, 8) == 0 && Bytes(sent.begin() + 22, sent.end() - 64) == expectedShort
        && verifyLocal(sent), "short message wire format and signature");
  uint64_t sentTs = sent.size() > 11 ? readBE64(&sent[3]) : 0;
  uint64_t nowMs = 0; currentEpochMilliseconds(&nowMs);
  CHECK(sentTs >= T0 && sentTs <= nowMs, "message timestamp from synchronized clock");

  out = feed([&] { Bytes r = sent; r[2] = 6; return r; }());
  CHECK(has(out, "self echo") && !has(out, "Content:"), "relayed copy of own message rejected");

  bitchatChar.writes.clear();
  std::string longOut; for (int i = 0; i < 30; i++) longOut += "送信テスト" + std::to_string(i) + " ";
  out = typeLine(longOut + "\r\n");
  Bytes rebuilt;
  CHECK(bitchatChar.writes.size() > 1 && has(out, "Fragmentation: ") && reassembleWrites(bitchatChar.writes, rebuilt, 7, 0x00)
        && rebuilt.size() == 22 + longOut.size() + 64 && Bytes(rebuilt.begin() + 22, rebuilt.end() - 64) == Bytes(longOut.begin(), longOut.end())
        && verifyLocal(rebuilt), "long message fragmented and reassembles to a valid signed packet");

  bitchatChar.writes.clear();
  out = typeLine(std::string(MAX_LOCAL_MESSAGE_BYTES + 1, 'a') + "\n");
  CHECK(has(out, "exceeds 1024 bytes") && bitchatChar.writes.empty(), "overlong input rejected");
  out = typeLine(std::string(MAX_LOCAL_MESSAGE_BYTES, 'b') + "\n");
  CHECK(bitchatChar.writes.size() > 1, "maximum-length input sent");
  bitchatChar.writes.clear();
  out = typeLine(std::string("bad \xC0\xAF\n"));
  CHECK(has(out, "invalid UTF-8") && bitchatChar.writes.empty(), "invalid UTF-8 input rejected");
  out = typeLine("\n\r\n");
  CHECK(bitchatChar.writes.empty() && !has(out, "MESSAGE TX"), "empty lines ignored");
  out = typeLine("partial");
  CHECK(bitchatChar.writes.empty(), "line without terminator is buffered");
  out = typeLine(" line\n");
  CHECK(bitchatChar.writes.size() == 1 && has(out, "Content: partial line\n"), "buffered line completes");

  // ---- REQUEST_SYNC for local messages ----
  // Cache now holds the last four messages: long, max-length, "partial line" and the one before.
  auto idOf = [](const Bytes& pkt) { Bytes in; in.push_back(pkt[1]); in.insert(in.end(), pkt.begin() + 14, pkt.begin() + 22);
    in.insert(in.end(), pkt.begin() + 3, pkt.begin() + 11); in.insert(in.end(), pkt.begin() + 22, pkt.begin() + 22 + readBE16(&pkt[12]));
    Bytes h = sha(in); return Bytes(h.begin(), h.begin() + 16); };
  std::vector<Bytes> cachedIds;
  for (int i = 0; i < LOCAL_MESSAGE_CACHE_SIZE; i++) {
    Bytes pk(localMessages[i].packet, localMessages[i].packet + localMessages[i].packetLength);
    cachedIds.push_back(idOf(pk));
    if (memcmp(localMessages[i].packetId, cachedIds.back().data(), 16) != 0) cachedIds.back().clear();
  }
  out = "";
  CHECK(std::all_of(cachedIds.begin(), cachedIds.end(), [](const Bytes& b) { return !b.empty(); }), "cached packet IDs match official definition");

  g_millis += 31000;  // new response window
  bitchatChar.writes.clear();
  std::vector<Bytes> present(cachedIds.begin(), cachedIds.begin() + 3);
  uint64_t reqTs = T0 + 20000;
  out = feed(requestSync(peer, reqTs, gcsEncode(present, 7, 4096), 0x0002));
  CHECK(count(out, "GCS membership: PRESENT") == 3 && count(out, "GCS membership: MISSING") == 1
        && has(out, "1 RSR MESSAGE QUEUED") && has(out, "ANNOUNCE not requested"), "only missing message queued");
  Serial.out.clear(); loop(); loop(); out = Serial.out;
  Bytes rsr;
  bool rsrOk = false;
  // Ignore the periodic local ANNOUNCE that the loop may also send.
  bitchatChar.writes.erase(std::remove_if(bitchatChar.writes.begin(), bitchatChar.writes.end(),
    [](const Bytes& w) { return w[1] == 0x01; }), bitchatChar.writes.end());
  if (bitchatChar.writes.size() == 1) { rsr = bitchatChar.writes[0]; rsrOk = rsr[2] == 0 && rsr[11] == 0x12 && verifyLocal(rsr); }
  else if (reassembleWrites(bitchatChar.writes, rsr, 0, 0x10)) rsrOk = verifyLocal(rsr) && rsr[2] == 0 && rsr[11] == 0x12;
  CHECK(rsrOk && has(out, "=== REQUEST_SYNC MESSAGE RESPONSE TX ===") && idOf(rsr) == cachedIds[3], "RSR message sent with TTL 0 and RSR flag");

  g_millis += 31000;
  bitchatChar.writes.clear();
  out = feed(requestSync(peer, reqTs + 1, gcsEncode(cachedIds, 7, 4096), 0x0003));
  Serial.out.clear(); loop(); loop();
  CHECK(count(out, "GCS membership: PRESENT") >= 4 && has(out, "MESSAGE response: not needed") && bitchatChar.writes.size() <= 1,
        "no message response when all are present");

  g_millis += 31000;
  bitchatChar.writes.clear();
  uint64_t since = nowMs + 3600ULL * 1000;
  out = feed(requestSync(peer, reqTs + 2, Bytes{0x00}, 0x0002, &since));
  CHECK(count(out, "before since cursor") == 4 && has(out, "not needed"), "since cursor respected");

  g_millis += 31000;
  out = feed(requestSync(peer, reqTs + 3, Bytes{0x00}, 0x0002));
  CHECK(has(out, "4 RSR MESSAGE QUEUED"), "all messages queued when filter is empty");
  bitchatChar.writes.clear(); Serial.out.clear(); loop(); loop(); out = Serial.out;
  std::vector<Bytes> rsrFragments;
  for (auto& w : bitchatChar.writes) if (w[1] == 0x20) rsrFragments.push_back(w);
  Bytes rsrLong;
  CHECK(reassembleWrites(rsrFragments, rsrLong, 0, 0x10) && rsrLong[2] == 0 && rsrLong[11] == 0x12 && verifyLocal(rsrLong),
        "fragmented RSR message keeps TTL 0 and RSR flag on fragments");
  disconnect_callback(0, 0x13);
  bitchatChar.writes.clear(); Serial.out.clear(); loop(); out = Serial.out;
  CHECK(bitchatChar.writes.empty() && localMessageResponsePendingMask == 0, "pending responses cleared on disconnect");
  out = typeLine("offline\n");
  CHECK(has(out, "no Bitchat link") && bitchatChar.writes.empty(), "send rejected while disconnected");

  out = feed(msg(peer, T0 + 10000, "after disconnect"));
  CHECK(has(out, "sender has no verified ANNOUNCE"), "peer cache cleared on disconnect");

  std::cout << (failures ? "FAILURES: " : "ALL PASSED ") << failures << "\n";
  return failures ? 1 : 0;
}
