/**
 * RADIUS / MS-CHAPv2 compliance test notes
 * - DES: Used for MS-CHAPv2 NT-Response (3x DES-ECB) via des.encrypt() on 8-byte blocks.
 * - MD4: Used for NT-Hash and NT-Hash-Hash via md4.reset()/update()/finalize().
 * - SHA1: Used for ChallengeHash and AuthenticatorResponse via Sha1.init()/write()/result().
 * - MD5: Used for RADIUS Response Authenticator via MD5_CTX + MD5::MD5Init/Update/Final
 *        so we can hash binary buffers (packet header + request authenticator + attrs + secret).
 * - HMAC-MD5: Used for Message-Authenticator via md5.hmac_md5(packet, len, key, key_len).
 *
 * Known adjustments:
 * - Response Authenticator must hash binary data; do not use md5.make_hash() for this path.
 * - For Access-Accept, compute Message-Authenticator with the request authenticator in the header,
 *   then insert the HMAC bytes before calculating the Response Authenticator.
 * - ChallengeHash uses first 8 bytes of SHA-1(PeerChallenge + AuthChallenge + UserName).
 * - NT-Response uses 21-byte zero-padded NT-Hash split into three 7-byte DES keys.
 */
#include <Arduino.h>
#include <SPI.h>
#include <SdFat.h>  // sdfat by Bill Greiman v2.2.3
#include <Ethernet.h>
#include <EthernetUdp.h>
#include "DES.h"
#include "MD5.h"
#include "SHA1.h"
#include "md4.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

DES des;
MD5 md5;
MD4 md4;
extern Sha1Class Sha1;

namespace {
const uint8_t kAuthenticator[16] = {
    0xE9, 0x2B, 0xB5, 0x6F, 0xED, 0x23, 0x8E, 0x61,
    0x54, 0xC3, 0xA1, 0xFE, 0x8B, 0x58, 0x8B, 0x4D
};

const uint8_t kAuthChallenge[16] = {
    0xD0, 0x9F, 0x6A, 0xB6, 0xE4, 0x69, 0xE5, 0x4E,
    0x86, 0xA2, 0xE1, 0x33, 0xE7, 0x8F, 0x9F, 0xAA
};

const uint8_t kPeerChallenge[16] = {
    0x56, 0x66, 0xFF, 0x64, 0xD8, 0x85, 0x6E, 0xE9,
    0x23, 0xB7, 0xAB, 0x7F, 0x10, 0x52, 0x6E, 0xD6
};

const char kUserName[] = "testuser";
const char kPassword[] = "testpass";
const char kSharedSecret[] = "testing123";

const char kExpectedNtHash[] = "35CCBA9168B1D5CA6093B4B7D56C619B";
const char kExpectedChallengeHash[] = "6EED142C27ED55A5";
const char kExpectedNtResponse[] = "0C03DFB3EE78A2DA208E23B8D0E5BF128F955B01904A21FC";
const char kExpectedNtHashHash[] = "8EFF585D2A73A2906DC517ED014BC58A";
const char kExpectedAuthenticatorResponse[] = "F5A73CDD7E42B9D3D1B5514908C687C92728A24E";
const char kExpectedMessageAuthenticator[] = "C958B4A1CC10997F7B243ADA738B97C0";
const char kExpectedResponseAuthenticator[] = "AB11F7DAD70FD916410D6426C46CEE64";
const char kExpectedResponseMessageAuthenticator[] = "0C63150F8CAE603258421EADBA4D946A";

const uint8_t kExpectedMessageAuthenticatorBytes[16] = {
    0xC9, 0x58, 0xB4, 0xA1, 0xCC, 0x10, 0x99, 0x7F,
    0x7B, 0x24, 0x3A, 0xDA, 0x73, 0x8B, 0x97, 0xC0
};

const uint8_t kExpectedResponseMessageAuthenticatorBytes[16] = {
    0x0C, 0x63, 0x15, 0x0F, 0x8C, 0xAE, 0x60, 0x32,
    0x58, 0x42, 0x1E, 0xAD, 0xBA, 0x4D, 0x94, 0x6A
};

const uint32_t kVendorIdMicrosoft = 311;
const uint8_t kAttrUserName = 1;
const uint8_t kAttrNasIpAddress = 4;
const uint8_t kAttrServiceType = 6;
const uint8_t kAttrVendorSpecific = 26;
const uint8_t kAttrCallingStationId = 31;
const uint8_t kAttrNasIdentifier = 32;
const uint8_t kAttrMessageAuthenticator = 80;
const uint8_t kVendorTypeMsChapChallenge = 11;
const uint8_t kVendorTypeMsChap2Response = 25;
const uint8_t kVendorTypeMsChap2Success = 26;
const uint8_t kVendorTypeMsMppeSendKey = 16;
const uint8_t kVendorTypeMsMppeRecvKey = 17;
const uint8_t kVendorTypeMsMppeEncryptionPolicy = 7;
const uint8_t kVendorTypeMsMppeEncryptionTypes = 8;

const uint8_t kServiceTypeLoginUser[4] = {0x00, 0x00, 0x00, 0x01};
const char kCallingStationId[] = "192.168.1.206";
const char kNasIdentifier[] = "SHED";
const uint8_t kNasIpAddress[4] = {192, 168, 1, 226};

const uint8_t kMppeRecvKey[34] = {
    0x81, 0x5E, 0xAD, 0x06, 0xB7, 0xF6, 0xCF, 0x22, 0xB6,
    0xFB, 0x45, 0x5E, 0x26, 0x1A, 0xD5, 0x5E, 0x72, 0xC0,
    0xD8, 0x9F, 0x67, 0xF4, 0xDF, 0x64, 0xCF, 0x7E, 0x70,
    0xFA, 0xA0, 0xA0, 0xC2, 0xD7, 0x60, 0x95
};

const uint8_t kMppeSendKey[34] = {
    0x8F, 0x30, 0x1D, 0x22, 0x5E, 0x60, 0x64, 0xEE, 0xD3,
    0x91, 0x2A, 0x3F, 0xF2, 0x0A, 0xC7, 0x02, 0x42, 0xF0,
    0x09, 0x5A, 0x7F, 0x79, 0x02, 0x98, 0xAC, 0xF2, 0x2F,
    0x1A, 0xA6, 0xE5, 0xCE, 0x8F, 0xCE, 0x8D
};

const uint8_t kMppeEncryptionPolicy[4] = {0x00, 0x00, 0x00, 0x01};
const uint8_t kMppeEncryptionTypes[4] = {0x00, 0x00, 0x00, 0x06};

const char kMagic1[] = "Magic server to client signing constant";
const char kMagic2[] = "Pad to make it do more than one iteration";
}  // namespace

// Runtime settings for the RADIUS listener. Adjust MAC/IP to your LAN before flashing.
constexpr bool kRunSelfTest = false;  // Set true to run the original hash self-tests at boot.

constexpr uint16_t kRadiusPort = 1812;
constexpr size_t kMaxRadiusPacket = 512;
constexpr size_t kMaxUsers = 8;
constexpr uint32_t kDuplicateWindowMs = 5000;

constexpr uint8_t kEthernetCsPin = 10;  // W5100/W5500 default
constexpr uint8_t kSdCsPin = 4;         // Arduino Ethernet shield default

constexpr char kUserFileName[] = "user.txt";
constexpr char kSecretFileName[] = "secret.txt";

byte kMacAddress[] = {0xA0, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE};
IPAddress kLocalIp(192, 168, 1, 111);
IPAddress kDnsServer(1, 1, 1, 1);
IPAddress kGateway(192, 168, 1, 1);
IPAddress kSubnet(255, 255, 255, 0);

SdFat sd;
EthernetUDP radiusUdp;

struct UserCredential {
  char username[64];
  char password[64];
};

struct RadiusDuplicate {
  IPAddress ip;
  uint8_t identifier;
  uint8_t authenticator[16];
  uint32_t lastSeenMs;
  bool inUse;
};

struct RadiusRequest {
  uint8_t buffer[kMaxRadiusPacket];
  size_t packetLen;
  uint8_t code;
  uint8_t identifier;
  uint16_t length;
  uint8_t authenticator[16];
  IPAddress remoteIp;
  uint16_t remotePort;
  bool hasMessageAuth;
  size_t messageAuthOffset;
  bool hasUsername;
  char username[64];
  bool hasMsChapChallenge;
  uint8_t msChapChallenge[16];
  bool hasMsChap2Response;
  uint8_t msChap2Response[50];
  uint8_t msChapV2Id;
};

struct MsChapV2Computed {
  uint8_t challenge[8];
  uint8_t ntHash[16];
  uint8_t ntHashHash[16];
  uint8_t ntResponse[24];
  uint8_t authResponse[20];
};

UserCredential gUsers[kMaxUsers];
size_t gUserCount = 0;
char gSharedSecret[64] = {0};
RadiusDuplicate gRecent[4];

void printHex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (data[i] < 0x10) {
      Serial.print("0");
    }
    Serial.print(data[i], HEX);
  }
}

void printHexLine(const uint8_t *data, size_t len) {
  printHex(data, len);
  Serial.println();
}

// Debug helper: hex dump similar to a short Wireshark view.
void dumpBuffer(const uint8_t *data, size_t len) {
  const size_t bytesPerLine = 16;
  for (size_t i = 0; i < len; i += bytesPerLine) {
    Serial.print(i, HEX);
    Serial.print(": ");
    const size_t lineLen = min(bytesPerLine, len - i);
    for (size_t j = 0; j < lineLen; ++j) {
      if (data[i + j] < 0x10) {
        Serial.print("0");
      }
      Serial.print(data[i + j], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

bool equalsHexIgnoreCase(const char *a, const char *b) {
  while (*a && *b) {
    char ca = *a++;
    char cb = *b++;
    if (ca >= 'a' && ca <= 'f') {
      ca = ca - 'a' + 'A';
    }
    if (cb >= 'a' && cb <= 'f') {
      cb = cb - 'a' + 'A';
    }
    if (ca != cb) {
      return false;
    }
  }
  return *a == '\0' && *b == '\0';
}

void bytesToHexString(const uint8_t *data, size_t len, char *out) {
  for (size_t i = 0; i < len; ++i) {
    sprintf(out + (i * 2), "%02X", data[i]);
  }
  out[len * 2] = '\0';
}

void trimTrailingWhitespace(char *s) {
  int end = static_cast<int>(strlen(s)) - 1;
  while (end >= 0 && (s[end] == ' ' || s[end] == '\r' || s[end] == '\n' || s[end] == '\t')) {
    s[end--] = '\0';
  }
}

bool readLine(File &file, char *buffer, size_t maxLen) {
  size_t pos = 0;
  while (file.available()) {
    int c = file.read();
    if (c < 0) {
      break;
    }
    if (c == '\r') {
      continue;
    }
    if (c == '\n') {
      break;
    }
    if (pos + 1 < maxLen) {
      buffer[pos++] = static_cast<char>(c);
    }
  }
  buffer[pos] = '\0';
  return pos > 0;
}

void ntPasswordHash(const char *password, uint8_t out[16]) {
  md4.reset();
  while (*password) {
    uint8_t pair[2] = { static_cast<uint8_t>(*password), 0x00 };
    md4.update(pair, sizeof(pair));
    ++password;
  }
  md4.finalize(out);
}

void ntPasswordHashHash(const uint8_t ntHash[16], uint8_t out[16]) {
  md4.reset();
  md4.update(ntHash, 16);
  md4.finalize(out);
}

void challengeHash(const uint8_t peerChallenge[16], const uint8_t authenticatorChallenge[16],
                   const char *username, uint8_t out[8]) {
  uint8_t digest[20];
  Sha1.init();
  Sha1.write(peerChallenge, 16);
  Sha1.write(authenticatorChallenge, 16);
  Sha1.write(reinterpret_cast<const uint8_t *>(username), strlen(username));
  memcpy(digest, Sha1.result(), sizeof(digest));
  memcpy(out, digest, 8);
}

void authenticatorResponse(const uint8_t ntHashHash[16], const uint8_t ntResponse[24],
                           const uint8_t challenge[8], uint8_t out[20]) {
  uint8_t digest[20];
  Sha1.init();
  Sha1.write(ntHashHash, 16);
  Sha1.write(ntResponse, 24);
  Sha1.write(reinterpret_cast<const uint8_t *>(kMagic1), strlen(kMagic1));
  memcpy(digest, Sha1.result(), sizeof(digest));

  Sha1.init();
  Sha1.write(digest, sizeof(digest));
  Sha1.write(challenge, 8);
  Sha1.write(reinterpret_cast<const uint8_t *>(kMagic2), strlen(kMagic2));
  memcpy(out, Sha1.result(), 20);
}

void setupDesKey(const uint8_t key7[7], uint8_t key8[8]) {
  key8[0] = key7[0] & 0xFE;
  key8[1] = ((key7[0] << 7) | (key7[1] >> 1)) & 0xFE;
  key8[2] = ((key7[1] << 6) | (key7[2] >> 2)) & 0xFE;
  key8[3] = ((key7[2] << 5) | (key7[3] >> 3)) & 0xFE;
  key8[4] = ((key7[3] << 4) | (key7[4] >> 4)) & 0xFE;
  key8[5] = ((key7[4] << 3) | (key7[5] >> 5)) & 0xFE;
  key8[6] = ((key7[5] << 2) | (key7[6] >> 6)) & 0xFE;
  key8[7] = (key7[6] << 1) & 0xFE;

  for (int i = 0; i < 8; ++i) {
    uint8_t parity = 1;
    for (int bit = 0; bit < 7; ++bit) {
      parity ^= (key8[i] >> bit) & 0x01;
    }
    key8[i] |= parity;
  }
}

void challengeResponse(const uint8_t ntHash[16], const uint8_t challenge[8], uint8_t out[24]) {
  uint8_t zpwd[21] = {0};
  memcpy(zpwd, ntHash, 16);

  for (int i = 0; i < 3; ++i) {
    uint8_t key7[7];
    uint8_t key8[8];
    memcpy(key7, zpwd + (i * 7), sizeof(key7));
    setupDesKey(key7, key8);
    des.encrypt(reinterpret_cast<byte *>(out + (i * 8)),
                reinterpret_cast<const byte *>(challenge),
                reinterpret_cast<const byte *>(key8));
  }
}

size_t appendAttribute(uint8_t *buffer, size_t offset, uint8_t type, const uint8_t *data, size_t len) {
  buffer[offset++] = type;
  buffer[offset++] = static_cast<uint8_t>(len + 2);
  memcpy(buffer + offset, data, len);
  return offset + len;
}

size_t appendVendorSpecific(uint8_t *buffer, size_t offset, uint8_t vendorType,
                            const uint8_t *data, size_t len) {
  const uint8_t vendorLen = static_cast<uint8_t>(len + 2);
  const uint8_t attrLen = static_cast<uint8_t>(vendorLen + 4 + 2);

  buffer[offset++] = kAttrVendorSpecific;
  buffer[offset++] = attrLen;
  buffer[offset++] = (kVendorIdMicrosoft >> 24) & 0xFF;
  buffer[offset++] = (kVendorIdMicrosoft >> 16) & 0xFF;
  buffer[offset++] = (kVendorIdMicrosoft >> 8) & 0xFF;
  buffer[offset++] = kVendorIdMicrosoft & 0xFF;
  buffer[offset++] = vendorType;
  buffer[offset++] = vendorLen;
  memcpy(buffer + offset, data, len);
  return offset + len;
}

bool loadSharedSecretFromSd() {
  File secret = sd.open(kSecretFileName, FILE_READ);
  if (!secret) {
    Serial.println("SD: secret.txt not found");
    return false;
  }

  char line[sizeof(gSharedSecret)];
  if (!readLine(secret, line, sizeof(line))) {
    Serial.println("SD: secret.txt is empty");
    secret.close();
    return false;
  }

  trimTrailingWhitespace(line);
  strncpy(gSharedSecret, line, sizeof(gSharedSecret) - 1);
  gSharedSecret[sizeof(gSharedSecret) - 1] = '\0';
  secret.close();
  Serial.print("SD: loaded shared secret (len=");
  Serial.print(strlen(gSharedSecret));
  Serial.println(")");
  return strlen(gSharedSecret) > 0;
}

bool loadUsersFromSd() {
  File users = sd.open(kUserFileName, FILE_READ);
  if (!users) {
    Serial.println("SD: user.txt not found");
    return false;
  }

  gUserCount = 0;
  char line[128];
  while (gUserCount < kMaxUsers && readLine(users, line, sizeof(line))) {
    trimTrailingWhitespace(line);
    if (strlen(line) == 0) {
      continue;
    }
    char *sep = strchr(line, ':');
    if (!sep) {
      continue;
    }
    *sep = '\0';
    const char *pw = sep + 1;

    strncpy(gUsers[gUserCount].username, line, sizeof(gUsers[gUserCount].username) - 1);
    gUsers[gUserCount].username[sizeof(gUsers[gUserCount].username) - 1] = '\0';
    strncpy(gUsers[gUserCount].password, pw, sizeof(gUsers[gUserCount].password) - 1);
    gUsers[gUserCount].password[sizeof(gUsers[gUserCount].password) - 1] = '\0';
    ++gUserCount;
  }

  users.close();
  Serial.print("SD: loaded users=");
  Serial.println(gUserCount);
  for (size_t i = 0; i < gUserCount; ++i) {
    Serial.print("  user[");
    Serial.print(i);
    Serial.print("]: ");
    Serial.println(gUsers[i].username);
  }
  return gUserCount > 0;
}

bool initSdCard() {
  pinMode(kEthernetCsPin, OUTPUT);
  digitalWrite(kEthernetCsPin, HIGH);  // keep W5x00 idle while touching SD

  if (!sd.begin(kSdCsPin)) {
    Serial.println("SD: init failed");
    return false;
  }

  const bool secretOk = loadSharedSecretFromSd();
  const bool usersOk = loadUsersFromSd();
  if (!secretOk) {
    Serial.println("SD: failed to load shared secret");
  }
  if (!usersOk) {
    Serial.println("SD: failed to load users");
  }
  return secretOk && usersOk;
}

bool initNetwork() {
  Ethernet.init(kEthernetCsPin);
  Ethernet.begin(kMacAddress, kLocalIp, kDnsServer, kGateway, kSubnet);

  delay(5000);  // allow link/DHCP-less init to settle before using IP

  if (Ethernet.localIP() == IPAddress(0, 0, 0, 0)) {
    Serial.println("Ethernet: init failed (check MAC/IP)");
    return false;
  }

  radiusUdp.begin(kRadiusPort);
  Serial.print("Ethernet: IP ");
  Serial.println(Ethernet.localIP());
  Serial.print("Ethernet: gateway ");
  Serial.println(kGateway);
  Serial.print("Ethernet: DNS ");
  Serial.println(kDnsServer);
  Serial.print("Ethernet: subnet ");
  Serial.println(kSubnet);
  return true;
}

void resetDuplicateTable() {
  for (size_t i = 0; i < sizeof(gRecent) / sizeof(gRecent[0]); ++i) {
    gRecent[i].inUse = false;
  }
}

bool isDuplicateRequest(const RadiusRequest &req) {
  const uint32_t now = millis();
  for (size_t i = 0; i < sizeof(gRecent) / sizeof(gRecent[0]); ++i) {
    if (!gRecent[i].inUse) {
      continue;
    }
    if (now - gRecent[i].lastSeenMs > kDuplicateWindowMs) {
      gRecent[i].inUse = false;
      continue;
    }
    if (gRecent[i].identifier == req.identifier &&
        gRecent[i].ip == req.remoteIp &&
        memcmp(gRecent[i].authenticator, req.authenticator, sizeof(req.authenticator)) == 0) {
      return true;
    }
  }
  return false;
}

void rememberRequest(const RadiusRequest &req) {
  size_t slot = 0;
  uint32_t oldest = UINT32_MAX;
  for (size_t i = 0; i < sizeof(gRecent) / sizeof(gRecent[0]); ++i) {
    if (!gRecent[i].inUse) {
      slot = i;
      break;
    }
    if (gRecent[i].lastSeenMs < oldest) {
      oldest = gRecent[i].lastSeenMs;
      slot = i;
    }
  }

  gRecent[slot].inUse = true;
  gRecent[slot].identifier = req.identifier;
  gRecent[slot].ip = req.remoteIp;
  memcpy(gRecent[slot].authenticator, req.authenticator, sizeof(req.authenticator));
  gRecent[slot].lastSeenMs = millis();
}

const char *lookupPassword(const char *username) {
  for (size_t i = 0; i < gUserCount; ++i) {
    if (strcmp(username, gUsers[i].username) == 0) {
      return gUsers[i].password;
    }
  }
  return nullptr;
}

bool parseRadiusRequest(RadiusRequest &req) {
  if (req.packetLen < 20) {
    Serial.println("RADIUS: packet too short");
    return false;
  }

  req.code = req.buffer[0];
  req.identifier = req.buffer[1];
  req.length = static_cast<uint16_t>((req.buffer[2] << 8) | req.buffer[3]);
  if (req.length != req.packetLen) {
    Serial.println("RADIUS: length mismatch");
    return false;
  }

  memcpy(req.authenticator, req.buffer + 4, 16);
  req.hasMessageAuth = false;
  req.hasUsername = false;
  req.hasMsChapChallenge = false;
  req.hasMsChap2Response = false;
  req.msChapV2Id = 0;

  size_t pos = 20;
  Serial.print("RADIUS: parsing attributes, len=");
  Serial.println(req.length);
  while (pos + 2 <= req.length) {
    uint8_t type = req.buffer[pos];
    uint8_t attrLen = req.buffer[pos + 1];
    if (attrLen < 2 || pos + attrLen > req.length) {
      Serial.println("RADIUS: bad attribute length");
      return false;
    }

    const uint8_t *value = req.buffer + pos + 2;
    const size_t valueLen = attrLen - 2;

    if (type == kAttrUserName) {
      const size_t copyLen = min(valueLen, sizeof(req.username) - 1);
      memcpy(req.username, value, copyLen);
      req.username[copyLen] = '\0';
      req.hasUsername = true;
    } else if (type == kAttrMessageAuthenticator && valueLen == 16) {
      req.hasMessageAuth = true;
      req.messageAuthOffset = pos;
    } else if (type == kAttrVendorSpecific && valueLen >= 6) {
      const uint32_t vendorId = (static_cast<uint32_t>(value[0]) << 24) |
                                (static_cast<uint32_t>(value[1]) << 16) |
                                (static_cast<uint32_t>(value[2]) << 8) |
                                static_cast<uint32_t>(value[3]);
      const uint8_t vendorType = value[4];
      const uint8_t vendorLen = value[5];

      if (vendorId == kVendorIdMicrosoft && vendorLen >= 2 && vendorLen <= valueLen - 4) {
        const uint8_t *vendorData = value + 6;
        const size_t vendorDataLen = vendorLen - 2;
        if (vendorType == kVendorTypeMsChapChallenge && vendorDataLen == 16) {
          memcpy(req.msChapChallenge, vendorData, 16);
          req.hasMsChapChallenge = true;
        } else if (vendorType == kVendorTypeMsChap2Response && vendorDataLen == 50) {
          memcpy(req.msChap2Response, vendorData, 50);
          req.msChapV2Id = vendorData[0];
          req.hasMsChap2Response = true;
        }
      }
    }

    pos += attrLen;
  }

  Serial.print("RADIUS: hasUser=");
  Serial.print(req.hasUsername);
  Serial.print(" hasChal=");
  Serial.print(req.hasMsChapChallenge);
  Serial.print(" hasResp=");
  Serial.print(req.hasMsChap2Response);
  Serial.print(" hasMsgAuth=");
  Serial.println(req.hasMessageAuth);

  return true;
}

bool verifyMessageAuthenticator(const RadiusRequest &req) {
  if (!req.hasMessageAuth) {
    return true;
  }

  if (strlen(gSharedSecret) == 0) {
    Serial.println("RADIUS: shared secret missing");
    return false;
  }

  uint8_t temp[kMaxRadiusPacket];
  memcpy(temp, req.buffer, req.length);
  memset(temp + req.messageAuthOffset + 2, 0x00, 16);

  char *computed = md5.hmac_md5(temp, req.length,
                                 reinterpret_cast<void *>(gSharedSecret),
                                 strlen(gSharedSecret));
  char received[33];
  bytesToHexString(req.buffer + req.messageAuthOffset + 2, 16, received);

  const bool ok = equalsHexIgnoreCase(computed, received);
  free(computed);
  if (!ok) {
    Serial.println("RADIUS: Message-Authenticator mismatch");
  } else {
    Serial.println("RADIUS: Message-Authenticator OK");
  }
  return ok;
}

bool computeMsChapV2(const RadiusRequest &req, const char *password, MsChapV2Computed &out) {
  if (!req.hasMsChapChallenge || !req.hasMsChap2Response) {
    return false;
  }

  uint8_t peerChallenge[16];
  memcpy(peerChallenge, req.msChap2Response + 2, 16);
  memcpy(out.ntResponse, req.msChap2Response + 26, 24);

  challengeHash(peerChallenge, req.msChapChallenge, req.username, out.challenge);
  ntPasswordHash(password, out.ntHash);
  challengeResponse(out.ntHash, out.challenge, out.ntResponse);

  if (memcmp(out.ntResponse, req.msChap2Response + 26, 24) != 0) {
    Serial.println("RADIUS: MS-CHAPv2 response mismatch");
    return false;
  }

  Serial.println("RADIUS: MS-CHAPv2 response OK");

  ntPasswordHashHash(out.ntHash, out.ntHashHash);
  authenticatorResponse(out.ntHashHash, out.ntResponse, out.challenge, out.authResponse);
  return true;
}

// Placeholders for other auth methods; not yet implemented.
void handlePapRequest(const RadiusRequest &) {}
void handleChapRequest(const RadiusRequest &) {}
void handleEapTlsRequest(const RadiusRequest &) {}

void sendAccessReject(const RadiusRequest &req, bool includeMessageAuth) {
  uint8_t packet[64];
  size_t offset = 0;
  packet[offset++] = 0x03;  // Access-Reject
  packet[offset++] = req.identifier;
  packet[offset++] = 0x00;  // Length placeholder
  packet[offset++] = 0x00;
  memset(packet + offset, 0x00, 16);  // Response authenticator placeholder
  offset += 16;

  size_t messageAuthOffset = 0;
  if (includeMessageAuth) {
    const uint8_t zeroed[16] = {0};
    messageAuthOffset = offset;
    offset = appendAttribute(packet, offset, kAttrMessageAuthenticator,
                             zeroed, sizeof(zeroed));
  }

  const uint16_t length = static_cast<uint16_t>(offset);
  packet[2] = (length >> 8) & 0xFF;
  packet[3] = length & 0xFF;

  if (includeMessageAuth) {
    uint8_t hmacInput[kMaxRadiusPacket];
    memcpy(hmacInput, packet, length);
    memcpy(hmacInput + 4, req.authenticator, 16);
    memset(hmacInput + messageAuthOffset + 2, 0x00, 16);

    char *messageAuth = md5.hmac_md5(hmacInput, length,
                                     reinterpret_cast<void *>(gSharedSecret),
                                     strlen(gSharedSecret));
    for (int i = 0; i < 16; ++i) {
      char byteChars[3] = {messageAuth[i * 2], messageAuth[i * 2 + 1], '\0'};
      packet[messageAuthOffset + 2 + i] = static_cast<uint8_t>(strtoul(byteChars, nullptr, 16));
    }
    free(messageAuth);
  }

  uint8_t responseAuthenticator[16];
  MD5_CTX ctx;
  MD5::MD5Init(&ctx);
  MD5::MD5Update(&ctx, packet, 4);
  MD5::MD5Update(&ctx, req.authenticator, 16);
  MD5::MD5Update(&ctx, packet + 20, length - 20);
  MD5::MD5Update(&ctx, gSharedSecret, strlen(gSharedSecret));
  MD5::MD5Final(responseAuthenticator, &ctx);
  memcpy(packet + 4, responseAuthenticator, sizeof(responseAuthenticator));

  radiusUdp.beginPacket(req.remoteIp, req.remotePort);
  radiusUdp.write(packet, length);
  radiusUdp.endPacket();
}

void sendAccessAccept(const RadiusRequest &req, const MsChapV2Computed &computed) {
  uint8_t packet[256];
  size_t offset = 0;
  packet[offset++] = 0x02;  // Access-Accept
  packet[offset++] = req.identifier;
  packet[offset++] = 0x00;  // Length placeholder
  packet[offset++] = 0x00;
  memset(packet + offset, 0x00, 16);  // Response authenticator placeholder
  offset += 16;

  const uint8_t zeroedMessageAuth[16] = {0};
  const size_t messageAuthOffset = offset;
  offset = appendAttribute(packet, offset, kAttrMessageAuthenticator,
                           zeroedMessageAuth, sizeof(zeroedMessageAuth));

  char authResponseHex[41];
  bytesToHexString(computed.authResponse, sizeof(computed.authResponse), authResponseHex);

  char successMessage[44];
  snprintf(successMessage, sizeof(successMessage), "S=%s", authResponseHex);

  uint8_t successPayload[48];
  const size_t successMsgLen = strlen(successMessage);
  successPayload[0] = req.msChapV2Id;
  memcpy(successPayload + 1, successMessage, successMsgLen);
  offset = appendVendorSpecific(packet, offset, kVendorTypeMsChap2Success,
                                successPayload, successMsgLen + 1);

  const uint16_t length = static_cast<uint16_t>(offset);
  packet[2] = (length >> 8) & 0xFF;
  packet[3] = length & 0xFF;

  uint8_t hmacInput[kMaxRadiusPacket];
  memcpy(hmacInput, packet, length);
  memcpy(hmacInput + 4, req.authenticator, 16);
  memset(hmacInput + messageAuthOffset + 2, 0x00, 16);

  char *messageAuth = md5.hmac_md5(hmacInput, length,
                                   reinterpret_cast<void *>(gSharedSecret),
                                   strlen(gSharedSecret));
  for (int i = 0; i < 16; ++i) {
    char byteChars[3] = {messageAuth[i * 2], messageAuth[i * 2 + 1], '\0'};
    packet[messageAuthOffset + 2 + i] = static_cast<uint8_t>(strtoul(byteChars, nullptr, 16));
  }
  free(messageAuth);

  uint8_t responseAuthenticator[16];
  MD5_CTX ctx;
  MD5::MD5Init(&ctx);
  MD5::MD5Update(&ctx, packet, 4);
  MD5::MD5Update(&ctx, req.authenticator, 16);
  MD5::MD5Update(&ctx, packet + 20, length - 20);
  MD5::MD5Update(&ctx, gSharedSecret, strlen(gSharedSecret));
  MD5::MD5Final(responseAuthenticator, &ctx);
  memcpy(packet + 4, responseAuthenticator, sizeof(responseAuthenticator));

  radiusUdp.beginPacket(req.remoteIp, req.remotePort);
  radiusUdp.write(packet, length);
  radiusUdp.endPacket();
}

void handleRadiusPacket() {
  RadiusRequest req;
  req.packetLen = radiusUdp.parsePacket();
  if (req.packetLen <= 0) {
    return;
  }

  req.remoteIp = radiusUdp.remoteIP();
  req.remotePort = radiusUdp.remotePort();

  Serial.print("RADIUS: pkt from ");
  Serial.print(req.remoteIp);
  Serial.print(":");
  Serial.print(req.remotePort);
  Serial.print(" len=");
  Serial.println(req.packetLen);

  if (req.packetLen > kMaxRadiusPacket) {
    Serial.println("RADIUS: packet too large, dropping");
    uint8_t sink[64];
    while (radiusUdp.available()) {
      radiusUdp.read(sink, sizeof(sink));
    }
    return;
  }

  req.packetLen = radiusUdp.read(req.buffer, kMaxRadiusPacket);

  Serial.println("RADIUS: raw dump");
  dumpBuffer(req.buffer, req.packetLen);

  if (!parseRadiusRequest(req)) {
    return;
  }

  if (isDuplicateRequest(req)) {
    Serial.println("RADIUS: duplicate detected, ignoring");
    return;
  }

  if (!verifyMessageAuthenticator(req)) {
    sendAccessReject(req, false);
    rememberRequest(req);
    return;
  }

  if (!req.hasUsername || !req.hasMsChapChallenge || !req.hasMsChap2Response) {
    Serial.println("RADIUS: missing required MS-CHAPv2 attributes");
    sendAccessReject(req, req.hasMessageAuth);
    rememberRequest(req);
    return;
  }

  const char *password = lookupPassword(req.username);
  if (!password) {
    Serial.println("RADIUS: unknown user");
    Serial.print("RADIUS: username seen -> ");
    Serial.println(req.username);
    Serial.print("RADIUS: loaded users=");
    Serial.println(gUserCount);
    sendAccessReject(req, req.hasMessageAuth);
    rememberRequest(req);
    return;
  }

  MsChapV2Computed computed;
  if (!computeMsChapV2(req, password, computed)) {
    sendAccessReject(req, req.hasMessageAuth);
    rememberRequest(req);
    return;
  }

  sendAccessAccept(req, computed);
  rememberRequest(req);
}

void testMsChapV2() {
  Serial.println("===== MS-CHAPv2 Test =====");
  uint8_t ntHash[16];
  uint8_t ntHashHash[16];
  uint8_t challenge[8];
  uint8_t ntResponse[24];
  uint8_t authResponse[20];

  ntPasswordHash(kPassword, ntHash);
  ntPasswordHashHash(ntHash, ntHashHash);
  challengeHash(kPeerChallenge, kAuthChallenge, kUserName, challenge);
  challengeResponse(ntHash, challenge, ntResponse);
  authenticatorResponse(ntHashHash, ntResponse, challenge, authResponse);

  Serial.print("NT Hash: ");
  printHexLine(ntHash, sizeof(ntHash));
  Serial.print("Expected: ");
  Serial.println(kExpectedNtHash);

  Serial.print("Challenge Hash: ");
  printHexLine(challenge, sizeof(challenge));
  Serial.print("Expected: ");
  Serial.println(kExpectedChallengeHash);

  Serial.print("NT Response: ");
  printHexLine(ntResponse, sizeof(ntResponse));
  Serial.print("Expected: ");
  Serial.println(kExpectedNtResponse);

  Serial.print("NT Hash Hash: ");
  printHexLine(ntHashHash, sizeof(ntHashHash));
  Serial.print("Expected: ");
  Serial.println(kExpectedNtHashHash);

  Serial.print("Authenticator Response: ");
  printHexLine(authResponse, sizeof(authResponse));
  Serial.print("Expected: ");
  Serial.println(kExpectedAuthenticatorResponse);

  Serial.println();
}

void testRadiusAccessRequest() {
  Serial.println("===== RADIUS Access-Request Test =====");

  uint8_t ntHash[16];
  uint8_t challenge[8];
  uint8_t ntResponse[24];
  ntPasswordHash(kPassword, ntHash);
  challengeHash(kPeerChallenge, kAuthChallenge, kUserName, challenge);
  challengeResponse(ntHash, challenge, ntResponse);

  uint8_t mschap2Response[50];
  size_t index = 0;
  mschap2Response[index++] = 0x00;  // Identifier
  mschap2Response[index++] = 0x00;  // Flags
  memcpy(mschap2Response + index, kPeerChallenge, sizeof(kPeerChallenge));
  index += sizeof(kPeerChallenge);
  memset(mschap2Response + index, 0x00, 8);
  index += 8;
  memcpy(mschap2Response + index, ntResponse, sizeof(ntResponse));

  uint8_t packet[163];
  size_t offset = 0;
  packet[offset++] = 0x01;  // Access-Request
  packet[offset++] = 0x3E;  // Identifier
  packet[offset++] = 0x00;  // Length (placeholder)
  packet[offset++] = 0x00;
  memcpy(packet + offset, kAuthenticator, sizeof(kAuthenticator));
  offset += sizeof(kAuthenticator);

  offset = appendAttribute(packet, offset, kAttrServiceType,
                           kServiceTypeLoginUser, sizeof(kServiceTypeLoginUser));
  offset = appendAttribute(packet, offset, kAttrUserName,
                           reinterpret_cast<const uint8_t *>(kUserName), strlen(kUserName));
  offset = appendVendorSpecific(packet, offset, kVendorTypeMsChapChallenge,
                                kAuthChallenge, sizeof(kAuthChallenge));
  offset = appendVendorSpecific(packet, offset, kVendorTypeMsChap2Response,
                                mschap2Response, sizeof(mschap2Response));
  offset = appendAttribute(packet, offset, kAttrCallingStationId,
                           reinterpret_cast<const uint8_t *>(kCallingStationId),
                           strlen(kCallingStationId));
  offset = appendAttribute(packet, offset, kAttrNasIdentifier,
                           reinterpret_cast<const uint8_t *>(kNasIdentifier),
                           strlen(kNasIdentifier));
  offset = appendAttribute(packet, offset, kAttrNasIpAddress,
                           kNasIpAddress, sizeof(kNasIpAddress));

  const uint8_t zeroedMessageAuth[16] = {0};
  offset = appendAttribute(packet, offset, kAttrMessageAuthenticator,
                           zeroedMessageAuth, sizeof(zeroedMessageAuth));

  const uint16_t length = static_cast<uint16_t>(offset);
  packet[2] = (length >> 8) & 0xFF;
  packet[3] = length & 0xFF;

  char *messageAuth = md5.hmac_md5(packet, length,
                                  reinterpret_cast<void *>(const_cast<char *>(kSharedSecret)),
                                  strlen(kSharedSecret));

  Serial.print("Packet Length: ");
  Serial.println(length);
  Serial.print("Message-Authenticator: ");
  for (size_t i = 0; i < strlen(messageAuth); ++i) {
    char c = messageAuth[i];
    if (c >= 'a' && c <= 'f') {
      c = c - 'a' + 'A';
    }
    Serial.print(c);
  }
  Serial.println();
  Serial.print("Expected: ");
  Serial.println(kExpectedMessageAuthenticator);

  if (equalsHexIgnoreCase(messageAuth, kExpectedMessageAuthenticator)) {
    Serial.println("Message-Authenticator matches expected.");
  } else {
    Serial.println("Message-Authenticator mismatch.");
  }

  free(messageAuth);
}

void testRadiusAccessAccept() {
  Serial.println("===== RADIUS Access-Accept Test =====");

  uint8_t ntHash[16];
  uint8_t ntHashHash[16];
  uint8_t challenge[8];
  uint8_t ntResponse[24];
  uint8_t authResponse[20];

  ntPasswordHash(kPassword, ntHash);
  ntPasswordHashHash(ntHash, ntHashHash);
  challengeHash(kPeerChallenge, kAuthChallenge, kUserName, challenge);
  challengeResponse(ntHash, challenge, ntResponse);
  authenticatorResponse(ntHashHash, ntResponse, challenge, authResponse);

  char authResponseHex[41];
  for (int i = 0; i < 20; ++i) {
    sprintf(authResponseHex + (i * 2), "%02X", authResponse[i]);
  }
  authResponseHex[40] = '\0';

  char successMessage[44];
  snprintf(successMessage, sizeof(successMessage), "S=%s", authResponseHex);

  uint8_t successPayload[43];
  successPayload[0] = 0x00;  // Identifier
  memcpy(successPayload + 1, successMessage, strlen(successMessage));

  uint8_t packet[197];
  size_t offset = 0;
  packet[offset++] = 0x02;  // Access-Accept
  packet[offset++] = 0x3E;  // Identifier
  packet[offset++] = 0x00;  // Length placeholder
  packet[offset++] = 0x00;
  memset(packet + offset, 0x00, 16);  // Response authenticator placeholder
  offset += 16;

  size_t responseMessageAuthOffset = offset;
  const uint8_t zeroedMessageAuth[16] = {0};
  offset = appendAttribute(packet, offset, kAttrMessageAuthenticator,
                           zeroedMessageAuth, sizeof(zeroedMessageAuth));

  offset = appendVendorSpecific(packet, offset, kVendorTypeMsChap2Success,
                                successPayload, sizeof(successPayload));

  offset = appendVendorSpecific(packet, offset, kVendorTypeMsMppeRecvKey,
                                kMppeRecvKey, sizeof(kMppeRecvKey));
  offset = appendVendorSpecific(packet, offset, kVendorTypeMsMppeSendKey,
                                kMppeSendKey, sizeof(kMppeSendKey));
  offset = appendVendorSpecific(packet, offset, kVendorTypeMsMppeEncryptionPolicy,
                                kMppeEncryptionPolicy, sizeof(kMppeEncryptionPolicy));
  offset = appendVendorSpecific(packet, offset, kVendorTypeMsMppeEncryptionTypes,
                                kMppeEncryptionTypes, sizeof(kMppeEncryptionTypes));

  const uint16_t length = static_cast<uint16_t>(offset);
  packet[2] = (length >> 8) & 0xFF;
  packet[3] = length & 0xFF;

  uint8_t hmacInput[197];
  memcpy(hmacInput, packet, length);
  memcpy(hmacInput + 4, kAuthenticator, sizeof(kAuthenticator));
  memset(hmacInput + responseMessageAuthOffset + 2, 0x00, 16);

  char *messageAuth = md5.hmac_md5(hmacInput, length,
                                  reinterpret_cast<void *>(const_cast<char *>(kSharedSecret)),
                                  strlen(kSharedSecret));
  for (int i = 0; i < 16; ++i) {
    char byteChars[3] = {messageAuth[i * 2], messageAuth[i * 2 + 1], '\0'};
    packet[responseMessageAuthOffset + 2 + i] = static_cast<uint8_t>(strtoul(byteChars, nullptr, 16));
  }

  uint8_t responseInput[256];
  size_t responseInputLen = 0;
  memcpy(responseInput + responseInputLen, packet, 4);
  responseInputLen += 4;
  memcpy(responseInput + responseInputLen, kAuthenticator, sizeof(kAuthenticator));
  responseInputLen += sizeof(kAuthenticator);
  memcpy(responseInput + responseInputLen, packet + 20, length - 20);
  responseInputLen += length - 20;
  memcpy(responseInput + responseInputLen, kSharedSecret, strlen(kSharedSecret));
  responseInputLen += strlen(kSharedSecret);

  uint8_t responseAuthenticatorBuf[16];
  MD5_CTX responseCtx;
  MD5::MD5Init(&responseCtx);
  MD5::MD5Update(&responseCtx, responseInput, responseInputLen);
  MD5::MD5Final(responseAuthenticatorBuf, &responseCtx);
  memcpy(packet + 4, responseAuthenticatorBuf, sizeof(responseAuthenticatorBuf));

  Serial.print("Packet Length: ");
  Serial.println(length);

  Serial.print("Response Authenticator: ");
  printHexLine(responseAuthenticatorBuf, sizeof(responseAuthenticatorBuf));
  Serial.print("Expected: ");
  Serial.println(kExpectedResponseAuthenticator);

  Serial.print("Message-Authenticator: ");
  for (size_t i = 0; i < strlen(messageAuth); ++i) {
    char c = messageAuth[i];
    if (c >= 'a' && c <= 'f') {
      c = c - 'a' + 'A';
    }
    Serial.print(c);
  }
  Serial.println();
  Serial.print("Expected: ");
  Serial.println(kExpectedResponseMessageAuthenticator);

  if (equalsHexIgnoreCase(messageAuth, kExpectedResponseMessageAuthenticator)) {
    Serial.println("Message-Authenticator matches expected.");
  } else {
    Serial.println("Message-Authenticator mismatch.");
  }

  free(messageAuth);
}

void setup() {
  Serial.begin(9600);
  delay(3000);

  resetDuplicateTable();

  if (!initSdCard()) {
    Serial.println("Setup: SD not ready, authentication will fail");
  }

  if (!initNetwork()) {
    Serial.println("Setup: Ethernet init failed");
  }

  if (kRunSelfTest) {
    testMsChapV2();
    testRadiusAccessRequest();
    testRadiusAccessAccept();
  }

  Serial.println("Setup: RADIUS listener ready");
}

void loop() {
  handleRadiusPacket();
}