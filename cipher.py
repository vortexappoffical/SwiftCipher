import os
import random

# SwiftCipher: Custom Symmetric Encryption Algorithm with 1024-bit key

# Initialization Vector (IV) size and block size
BLOCK_SIZE = 16  # 128 bits
KEY_SIZE = 128  # 1024 bits

# S-Box
SBOX = [
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
]

# Inverse S-Box
INV_SBOX = [
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
]

# RCON
RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

# Key Scheduling (Round Key Generation)
def key_expansion(key):
    expanded_keys = [key]
    for i in range(1, 11):
        prev_key = expanded_keys[-1]
        t = prev_key[-4:]  # Last 4 bytes
        t = [SBOX[b] for b in t]  # Apply S-box
        t[0] ^= RCON[i]
        new_key = [prev_key[j] ^ t[j % 4] for j in range(16)]
        expanded_keys.append(new_key)
    return expanded_keys


# XOR operation
def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

# Add Round Key
def add_round_key(state, round_key):
    return xor_bytes(state, round_key)

# Sub Bytes using S-Box
def sub_bytes(state):
    return bytes(SBOX[b] for b in state)

# Inverse Sub Bytes using Inverse S-Box
def inv_sub_bytes(state):
    return bytes(INV_SBOX[b] for b in state)

# Shift Rows
def shift_rows(state):
    return bytes([state[0], state[5], state[10], state[15],
                  state[4], state[9], state[14], state[3],
                  state[8], state[13], state[2], state[7],
                  state[12], state[1], state[6], state[11]])

# Inverse Shift Rows
def inv_shift_rows(state):
    return bytes([state[0], state[13], state[10], state[7],
                  state[4], state[1], state[14], state[11],
                  state[8], state[5], state[2], state[15],
                  state[12], state[9], state[6], state[3]])

# Helper function for Galois Field (GF(2^8)) multiplication
def xtime(x):
    return (x << 1) ^ (0x11B if x & 0x80 else 0)

# MixColumns transformation for encryption
def mix_columns(state):
    # Matrix for MixColumns
    mix_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    # Create a list for the new state
    new_state = []

    # Perform matrix multiplication for each column
    for i in range(0, 16, 4):  # 4 columns (state is 4x4)
        column = [state[i], state[i+1], state[i+2], state[i+3]]

        # Multiply each column by the matrix (GF(2^8) operations)
        new_column = []
        for row in range(4):
            new_value = 0
            for col in range(4):
                # Galois Field multiplication and XOR operation
                new_value ^= gmul(mix_matrix[row][col], column[col])
            new_column.append(new_value)

        # Add the new column values to the new state
        new_state.extend(new_column)

    return bytes(new_state)

# Galois Field (GF(2^8)) multiplication
def gmul(a, b):
    result = 0
    while a and b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

# Inverse MixColumns transformation for decryption
def inv_mix_columns(state):
    # Matrix for Inverse MixColumns
    inv_mix_matrix = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ]

    # Create a list for the new state
    new_state = []

    # Perform matrix multiplication for each column
    for i in range(0, 16, 4):  # 4 columns (state is 4x4)
        column = [state[i], state[i+1], state[i+2], state[i+3]]

        # Multiply each column by the inverse matrix (GF(2^8) operations)
        new_column = []
        for row in range(4):
            new_value = 0
            for col in range(4):
                # Galois Field multiplication and XOR operation
                new_value ^= gmul(inv_mix_matrix[row][col], column[col])
            new_column.append(new_value)

        # Add the new column values to the new state
        new_state.extend(new_column)

    return bytes(new_state)


# Padding (PKCS#7)
def pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

# Unpadding (PKCS#7)
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_block(plaintext, key):
    state = plaintext
    round_keys = key_expansion(key)

    state = add_round_key(state, round_keys[0])
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)  # Use the updated MixColumns transformation
        state = add_round_key(state, round_keys[i])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return state


def decrypt_block(ciphertext, key):
    state = ciphertext
    round_keys = key_expansion(key)

    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for i in range(9, 0, -1):
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)  # Use the updated InverseMixColumns transformation
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    state = add_round_key(state, round_keys[0])
    return state


# Key generation
def generate_key():
    return os.urandom(KEY_SIZE // 8)

# Encrypt text (strings)
def encrypt_text(plaintext, key):
    plaintext = pad(plaintext)  # Remove the .encode() method since it's already in bytes
    iv = os.urandom(BLOCK_SIZE)
    ciphertext = iv
    prev_block = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        block = xor_bytes(block, prev_block)
        encrypted_block = encrypt_block(block, key)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext


# Decrypt text (bytes)
def decrypt_text(ciphertext, key):
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext = ciphertext[BLOCK_SIZE:]
    prev_block = iv
    decrypted_data = b''

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(block, key)
        decrypted_block = xor_bytes(decrypted_block, prev_block)
        decrypted_data += decrypted_block
        prev_block = block

    # Return the decrypted data as bytes, not a string
    return unpad(decrypted_data)


# Encrypt file
def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = encrypt_text(plaintext, key)
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

# Decrypt file (binary data)
def decrypt_file(input_encrypted_file, output_decrypted_file, key):
    with open(input_encrypted_file, 'rb') as f_in:
        ciphertext = f_in.read()

    decrypted_data = decrypt_text(ciphertext, key)

    # Write decrypted data as bytes (no decoding to string)
    with open(output_decrypted_file, 'wb') as f_out:
        f_out.write(decrypted_data)

# Load key from file
def load_key_from_file(filename):
    try:
        with open(filename, 'rb') as f:
            key = f.read()
        return key
    except Exception as e:
        print(f"Error loading key from file: {e}")
        return None

# Save key to file
def save_key_to_file(key, filename):
    try:
        with open(filename, 'wb') as f:
            f.write(key)
        print(f"Key saved to {filename}")
    except Exception as e:
        print(f"Error saving key to file: {e}")
