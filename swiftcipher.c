#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h> // OpenSSL's random number generator

// S-Box and Inverse S-Box
static const uint8_t S_BOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t INV_S_BOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants
static const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// Block size and key length definitions (Same as your original implementation)
#define BLOCK_SIZE 16
#define KEY_SIZE 1024  // Set key size to 1024 bits (128 bytes)
#define ROUND_KEYS 80

typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t roundKeys[ROUND_KEYS][BLOCK_SIZE];
} SwiftCipherKey;

void KeyExpansion(const uint8_t* key, SwiftCipherKey* cipherKey) {
    uint8_t temp[4];
    uint8_t i, j;
    for (i = 0; i < 16; i++) {
        cipherKey->roundKeys[0][i] = key[i];
    }

    for (i = 1; i < 80; i++) {
        for (j = 0; j < 4; j++) {
            temp[j] = cipherKey->roundKeys[i - 1][j + 12];
        }

        if (i % 16 == 0) {
            uint8_t k = temp[0];
            temp[0] = S_BOX[temp[1]] ^ RCON[i / 16 - 1];
            temp[1] = S_BOX[temp[2]];
            temp[2] = S_BOX[temp[3]];
            temp[3] = S_BOX[k];
        }

        for (j = 0; j < 16; j++) {
            cipherKey->roundKeys[i][j] = cipherKey->roundKeys[i - 1][j] ^ temp[j % 4];
        }
    }
}

void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] ^= roundKey[i];
    }
}

void SubBytes(uint8_t* state) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = S_BOX[state[i]];
    }
}

void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = INV_S_BOX[state[i]];
    }
}

void ShiftRows(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];
    memcpy(temp, state, BLOCK_SIZE);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i * 4 + j] = temp[i * 4 + ((j + i) % 4)];
        }
    }
}

void InvShiftRows(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];
    memcpy(temp, state, BLOCK_SIZE);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i * 4 + j] = temp[i * 4 + ((j - i + 4) % 4)];
        }
    }
}

void MixColumns(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];
    for (int i = 0; i < 4; i++) {
        temp[i * 4] = (uint8_t) (0x2 * state[i * 4] ^ 0x3 * state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3]);
        temp[i * 4 + 1] = (uint8_t) (state[i * 4] ^ 0x2 * state[i * 4 + 1] ^ 0x3 * state[i * 4 + 2] ^ state[i * 4 + 3]);
        temp[i * 4 + 2] = (uint8_t) (state[i * 4] ^ state[i * 4 + 1] ^ 0x2 * state[i * 4 + 2] ^ 0x3 * state[i * 4 + 3]);
        temp[i * 4 + 3] = (uint8_t) (0x3 * state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ 0x2 * state[i * 4 + 3]);
    }
    memcpy(state, temp, BLOCK_SIZE);
}

void InvMixColumns(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];
    for (int i = 0; i < 4; i++) {
        temp[i * 4] = (uint8_t) (0xe * state[i * 4] ^ 0xb * state[i * 4 + 1] ^ 0xd * state[i * 4 + 2] ^ 0x9 * state[i * 4 + 3]);
        temp[i * 4 + 1] = (uint8_t) (0x9 * state[i * 4] ^ 0xe * state[i * 4 + 1] ^ 0xb * state[i * 4 + 2] ^ 0xd * state[i * 4 + 3]);
        temp[i * 4 + 2] = (uint8_t) (0xd * state[i * 4] ^ 0x9 * state[i * 4 + 1] ^ 0xe * state[i * 4 + 2] ^ 0xb * state[i * 4 + 3]);
        temp[i * 4 + 3] = (uint8_t) (0xb * state[i * 4] ^ 0xd * state[i * 4 + 1] ^ 0x9 * state[i * 4 + 2] ^ 0xe * state[i * 4 + 3]);
    }
    memcpy(state, temp, BLOCK_SIZE);
}

// Encryption function with chaining mechanism (depends on both previous ciphertext and previous plaintext)
void EncryptBlock(uint8_t* block, uint8_t* prevBlock, const SwiftCipherKey* cipherKey, uint8_t* iv) {
    // XOR current block with IV and previous ciphertext
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= iv[i] ^ prevBlock[i];
    }
    AddRoundKey(block, cipherKey->roundKeys[0]);

    for (int round = 1; round < 10; round++) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, cipherKey->roundKeys[round]);
    }

    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, cipherKey->roundKeys[ROUND_KEYS - 1]);

    // Update previous block (ciphertext)
    memcpy(prevBlock, block, BLOCK_SIZE);
}

// Decryption function with chaining mechanism
void DecryptBlock(uint8_t* block, uint8_t* prevBlock, const SwiftCipherKey* cipherKey, uint8_t* iv) {
    AddRoundKey(block, cipherKey->roundKeys[ROUND_KEYS - 1]);

    for (int round = ROUND_KEYS - 2; round > 0; round--) {
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, cipherKey->roundKeys[round]);
        InvMixColumns(block);
    }

    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, cipherKey->roundKeys[0]);

    // XOR with previous ciphertext and IV for final decryption
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= iv[i] ^ prevBlock[i];
    }

    // Update previous block (ciphertext)
    memcpy(prevBlock, block, BLOCK_SIZE);
}
// Function to generate SwiftCipher key using OpenSSL's random number generator
void generate_swiftcipher_key(SwiftCipherKey* cipherKey) {
    if (RAND_bytes(cipherKey->key, KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating random key with OpenSSL.\n");
        exit(1);
    }
    KeyExpansion(cipherKey->key, cipherKey);
}

// Encrypt and Decrypt functions for text and files
void EncryptText(const char* text, uint8_t* output, const SwiftCipherKey* cipherKey, uint8_t* iv) {
    uint8_t block[BLOCK_SIZE];
    uint8_t prevBlock[BLOCK_SIZE] = {0};

    size_t len = strlen(text);
    size_t paddedLen = (len + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; // Pad to the nearest BLOCK_SIZE
    uint8_t* paddedText = (uint8_t*) malloc(paddedLen);
    memcpy(paddedText, text, len);
    memset(paddedText + len, 0, paddedLen - len); // Zero padding

    for (size_t i = 0; i < paddedLen; i += BLOCK_SIZE) {
        memcpy(block, paddedText + i, BLOCK_SIZE);
        EncryptBlock(block, prevBlock, cipherKey, iv);
        memcpy(output + i, block, BLOCK_SIZE);
    }

    free(paddedText);
}

void DecryptText(const uint8_t* encryptedText, char* output, const SwiftCipherKey* cipherKey, uint8_t* iv) {
    uint8_t block[BLOCK_SIZE];
    uint8_t prevBlock[BLOCK_SIZE] = {0};

    size_t len = strlen((char*) encryptedText);
    size_t paddedLen = (len / BLOCK_SIZE) * BLOCK_SIZE;
    uint8_t* decryptedText = (uint8_t*) malloc(paddedLen);

    for (size_t i = 0; i < paddedLen; i += BLOCK_SIZE) {
        memcpy(block, encryptedText + i, BLOCK_SIZE);
        DecryptBlock(block, prevBlock, cipherKey, iv);
        memcpy(decryptedText + i, block, BLOCK_SIZE);
    }

    // Remove padding and convert to string
    size_t textLen = paddedLen;
    while (textLen > 0 && decryptedText[textLen - 1] == 0) {
        textLen--;
    }

    memcpy(output, decryptedText, textLen);
    output[textLen] = '\0';

    free(decryptedText);
}

void EncryptFile(const char* inputFile, const char* outputFile, const SwiftCipherKey* cipherKey, uint8_t* iv) {
    FILE* in = fopen(inputFile, "rb");
    FILE* out = fopen(outputFile, "wb");

    if (!in || !out) {
        fprintf(stderr, "Error opening file.\n");
        exit(1);
    }

    uint8_t block[BLOCK_SIZE];
    uint8_t prevBlock[BLOCK_SIZE] = {0};
    size_t bytesRead;

    while ((bytesRead = fread(block, 1, BLOCK_SIZE, in)) > 0) {
        EncryptBlock(block, prevBlock, cipherKey, iv);
        fwrite(block, 1, bytesRead, out);
    }

    fclose(in);
    fclose(out);
}

void DecryptFile(const char* inputFile, const char* outputFile, const SwiftCipherKey* cipherKey, uint8_t* iv) {
    FILE* in = fopen(inputFile, "rb");
    FILE* out = fopen(outputFile, "wb");

    if (!in || !out) {
        fprintf(stderr, "Error opening file.\n");
        exit(1);
    }

    uint8_t block[BLOCK_SIZE];
    uint8_t prevBlock[BLOCK_SIZE] = {0};
    size_t bytesRead;

    while ((bytesRead = fread(block, 1, BLOCK_SIZE, in)) > 0) {
        DecryptBlock(block, prevBlock, cipherKey, iv);
        fwrite(block, 1, bytesRead, out);
    }

    fclose(in);
    fclose(out);
}
