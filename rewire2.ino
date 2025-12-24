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
#include "DES.h"
#include "MD5.h"
#include "SHA1.h"
#include "md4.h"
#include <string.h>
#include <stdlib.h>

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
  testMsChapV2();
  testRadiusAccessRequest();
  testRadiusAccessAccept();
}

void loop() {}