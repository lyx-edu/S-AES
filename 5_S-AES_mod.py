import tkinter as tk
from tkinter import messagebox
import random

# 定义 S 盒和逆 S 盒
S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_S_BOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

# 密钥扩展函数
def key_expansion(key):
    w = [0] * 6
    w[0] = (key & 0xFF00) >> 8
    w[1] = key & 0x00FF
    w[2] = w[0] ^ 0x80 ^ sub_nibble(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ 0x30 ^ sub_nibble(w[3])
    w[5] = w[4] ^ w[3]
    return w

# 密钥扩展替换
def sub_nibble(nibble):
    return ( S_BOX[nibble & 0x0F]<< 4) | S_BOX[(nibble & 0xF0) >> 4]

# 字节替代函数
def sub_bytes(state):
    return (
        (S_BOX[(state & 0xF000) >> 12] << 12) |
        (S_BOX[(state & 0x0F00) >> 8] << 8) |
        (S_BOX[(state & 0x00F0) >> 4] << 4) |
        (S_BOX[state & 0x000F])
    )

# 逆字节替代函数
def inv_sub_bytes(state):
    return (
        (INV_S_BOX[(state & 0xF000) >> 12] << 12) |
        (INV_S_BOX[(state & 0x0F00) >> 8] << 8) |
        (INV_S_BOX[(state & 0x00F0) >> 4] << 4) |
        (INV_S_BOX[state & 0x000F])
    )

# 轮密钥加函数
def add_round_key(state, key):
    return state ^ key

# 行移位操作
def shift_rows(state):
    row0 = (state & 0xF0F0)
    row1 = ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)
    return row0 | row1 

# 列混合操作
def mix_columns(state):
    t0 = (state & 0xF000) >> 12
    t2 = (state & 0x0F00) >> 8
    t1 = (state & 0x00F0) >> 4
    t3 = state & 0x000F
    return ((t0 ^ mul4(t2)) << 12) | ((t2 ^ mul4(t0)) << 8) | ((t1 ^ mul4(t3)) << 4) | (t3 ^ mul4(t1))

# 逆列混合操作
def inv_mix_columns(state):
    t0 = (state & 0xF000) >> 12
    t2 = (state & 0x0F00) >> 8
    t1 = (state & 0x00F0) >> 4
    t3 = state & 0x000F
    return ((mul9(t0) ^ mul2(t2)) << 12) | ((mul2(t0) ^ mul9(t2)) << 8) | ((mul9(t1) ^ mul2(t3)) << 4) | (mul2(t1) ^ mul9(t3))

# GF(2^4) 下乘 2
def mul2(nibble):
    return ((nibble << 1) & 0xF) ^ 0x3 if (nibble & 0x8) else (nibble << 1) & 0xF

# GF(2^4) 下乘 4
def mul4(nibble):
    return mul2(mul2(nibble)) & 0xF

# GF(2^4) 下乘 9
def mul9(nibble):
    return (mul4(mul2(nibble)) ^ nibble) & 0xF

# 加密函数
def s_aes_encrypt(plaintext, key):
    w = key_expansion(key)
    state = add_round_key(plaintext, (w[0] << 8) | w[1])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, (w[2] << 8) | w[3])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, (w[4] << 8) | w[5])
    return state

# 解密函数
def s_aes_decrypt(ciphertext, key):
    w = key_expansion(key)
    state = add_round_key(ciphertext, (w[4] << 8) | w[5])
    state = shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, (w[2] << 8) | w[3])
    state = inv_mix_columns(state)
    state = shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, (w[0] << 8) | w[1])
    return state

# CBC 加密函数
def encrypt_cbc(plaintext_blocks, key):
    iv = random.randint(0, 0xFFFF)  # 随机生成16位IV
    ciphertext_blocks = [iv]  # 第一个密文块为IV
    for plaintext in plaintext_blocks:
        xor_result = plaintext ^ ciphertext_blocks[-1]  # 与前一个密文块XOR
        encrypted_block = s_aes_encrypt(xor_result, key)  # 加密
        ciphertext_blocks.append(encrypted_block)  # 保存密文块
    return ciphertext_blocks

# CBC 解密函数
def decrypt_cbc(ciphertext_blocks, key):
    iv = ciphertext_blocks[0]  # 第一个密文块为IV
    plaintext_blocks = []
    for i in range(1, len(ciphertext_blocks)):
        decrypted_block = s_aes_decrypt(ciphertext_blocks[i], key)
        plaintext = decrypted_block ^ ciphertext_blocks[i - 1]  # 与前一个密文块XOR还原明文
        plaintext_blocks.append(plaintext)
    return plaintext_blocks

# 测试 CBC 加密和篡改
def test_cbc_with_tampering():
    # 输入明文和密钥
    plaintext_blocks = [0x1234, 0x5678]  # 示例明文块
    key = 0b0011001100110001  # 示例16位密钥
    
    # CBC 加密
    ciphertext_blocks = encrypt_cbc(plaintext_blocks, key)
    print("Original Ciphertext Blocks:", [format(c, '016b') for c in ciphertext_blocks])

    # 篡改密文
    tampered_ciphertext_blocks = ciphertext_blocks[:]
    tampered_ciphertext_blocks[1] ^= 0x0001  # 改变第一个实际密文块的一位
    print("Tampered Ciphertext Blocks:", [format(c, '016b') for c in tampered_ciphertext_blocks])

    # 解密原始和篡改密文
    original_plaintext_blocks = decrypt_cbc(ciphertext_blocks, key)
    tampered_plaintext_blocks = decrypt_cbc(tampered_ciphertext_blocks, key)

    print("Decrypted Plaintext Blocks (Original):", [format(p, '016b') for p in original_plaintext_blocks])
    print("Decrypted Plaintext Blocks (Tampered):", [format(p, '016b') for p in tampered_plaintext_blocks])

# 运行测试
test_cbc_with_tampering()
