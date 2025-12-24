#ifndef MD4_H
#define MD4_H

#include <Arduino.h>

class MD4 {
public:
    MD4();
    void update(const uint8_t *data, size_t len);
    void finalize(uint8_t *digest);
    void reset();

    // MS-CHAP v2 specific functions
    void msChapV2ChallengeHash(const uint8_t *peerChallenge, const uint8_t *authenticatorChallenge, const uint8_t *username, uint8_t *challenge);
    void msChapV2GenerateResponse(const uint8_t *passwordHash, const uint8_t *challenge, const uint8_t *peerChallenge, const uint8_t *username, uint8_t *response);

private:
    void transform(const uint8_t block[64]);
    void encode(uint8_t *output, const uint32_t *input, size_t len);
    void decode(uint32_t *output, const uint8_t *input, size_t len);

    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

#endif
