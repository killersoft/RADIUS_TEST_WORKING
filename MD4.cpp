#include "MD4.h"
#include <string.h>

#define md4F(x, y, z) ((x & y) | (~x & z))
#define md4G(x, y, z) ((x & y) | (x & z) | (y & z))
#define md4H(x, y, z) (x ^ y ^ z)

#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))

#define FF(a, b, c, d, x, s) { a += md4F(b, c, d) + x; a = ROTATE_LEFT(a, s); }
#define GG(a, b, c, d, x, s) { a += md4G(b, c, d) + x + (uint32_t)0x5a827999; a = ROTATE_LEFT(a, s); }
#define HH(a, b, c, d, x, s) { a += md4H(b, c, d) + x + (uint32_t)0x6ed9eba1; a = ROTATE_LEFT(a, s); }

MD4::MD4() {
    reset();
}

void MD4::update(const uint8_t *data, size_t len) {
    size_t i, index, partLen;

    index = (count[0] >> 3) & 0x3F;
    if ((count[0] += ((uint32_t)len << 3)) < ((uint32_t)len << 3)) {
        count[1]++;
    }
    count[1] += ((uint32_t)len >> 29);
    partLen = 64 - index;

    if (len >= partLen) {
        memcpy(&buffer[index], data, partLen);
        transform(buffer);

        for (i = partLen; i + 63 < len; i += 64) {
            transform(&data[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&buffer[index], &data[i], len - i);
}

void MD4::finalize(uint8_t *digest) {
    uint8_t bits[8];
    size_t index, padLen;

    encode(bits, count, 8);

    index = (count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    static const uint8_t padding[64] = { 0x80 };
    update(padding, padLen);
    update(bits, 8);

    encode(digest, state, 16);

    reset();
}

void MD4::reset() {
    count[0] = count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
    memset(buffer, 0, sizeof(buffer));
}

void MD4::transform(const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    decode(x, block, 64);

    FF(a, b, c, d, x[0], 3);
    FF(d, a, b, c, x[1], 7);
    FF(c, d, a, b, x[2], 11);
    FF(b, c, d, a, x[3], 19);
    FF(a, b, c, d, x[4], 3);
    FF(d, a, b, c, x[5], 7);
    FF(c, d, a, b, x[6], 11);
    FF(b, c, d, a, x[7], 19);
    FF(a, b, c, d, x[8], 3);
    FF(d, a, b, c, x[9], 7);
    FF(c, d, a, b, x[10], 11);
    FF(b, c, d, a, x[11], 19);
    FF(a, b, c, d, x[12], 3);
    FF(d, a, b, c, x[13], 7);
    FF(c, d, a, b, x[14], 11);
    FF(b, c, d, a, x[15], 19);

    GG(a, b, c, d, x[0], 3);
    GG(d, a, b, c, x[4], 5);
    GG(c, d, a, b, x[8], 9);
    GG(b, c, d, a, x[12], 13);
    GG(a, b, c, d, x[1], 3);
    GG(d, a, b, c, x[5], 5);
    GG(c, d, a, b, x[9], 9);
    GG(b, c, d, a, x[13], 13);
    GG(a, b, c, d, x[2], 3);
    GG(d, a, b, c, x[6], 5);
    GG(c, d, a, b, x[10], 9);
    GG(b, c, d, a, x[14], 13);
    GG(a, b, c, d, x[3], 3);
    GG(d, a, b, c, x[7], 5);
    GG(c, d, a, b, x[11], 9);
    GG(b, c, d, a, x[15], 13);

    HH(a, b, c, d, x[0], 3);
    HH(d, a, b, c, x[8], 9);
    HH(c, d, a, b, x[4], 11);
    HH(b, c, d, a, x[12], 15);
    HH(a, b, c, d, x[2], 3);
    HH(d, a, b, c, x[10], 9);
    HH(c, d, a, b, x[6], 11);
    HH(b, c, d, a, x[14], 15);
    HH(a, b, c, d, x[1], 3);
    HH(d, a, b, c, x[9], 9);
    HH(c, d, a, b, x[5], 11);
    HH(b, c, d, a, x[13], 15);
    HH(a, b, c, d, x[3], 3);
    HH(d, a, b, c, x[11], 9);
    HH(c, d, a, b, x[7], 11);
    HH(b, c, d, a, x[15], 15);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

void MD4::encode(uint8_t *output, const uint32_t *input, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (uint8_t)(input[i] & 0xff);
        output[j + 1] = (uint8_t)((input[i] >> 8) & 0xff);
        output[j + 2] = (uint8_t)((input[i] >> 16) & 0xff);
        output[j + 3] = (uint8_t)((input[i] >> 24) & 0xff);
    }
}

void MD4::decode(uint32_t *output, const uint8_t *input, size_t len) {
    for (size_t i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) |
                    (((uint32_t)input[j + 1]) << 8) |
                    (((uint32_t)input[j + 2]) << 16) |
                    (((uint32_t)input[j + 3]) << 24);
    }
}

// MS-CHAP v2 specific functions
void MD4::msChapV2ChallengeHash(const uint8_t *peerChallenge, const uint8_t *authenticatorChallenge, const uint8_t *username, uint8_t *challenge) {
    reset();
    update(peerChallenge, 16);
    update(authenticatorChallenge, 16);
    update(username, strlen((const char*)username));
    finalize(challenge);
}
// MS-CHAP v2 specific functions
void MD4::msChapV2GenerateResponse(const uint8_t *passwordHash, const uint8_t *challenge, const uint8_t *peerChallenge, const uint8_t *username, uint8_t *response) {
    uint8_t challengeHash[16];
    msChapV2ChallengeHash(peerChallenge, challenge, username, challengeHash);

    reset();
    update(passwordHash, 16);
    update(challengeHash, 8);  // MS-CHAP v2 uses the first 8 bytes of the challenge hash
    finalize(response);
}
