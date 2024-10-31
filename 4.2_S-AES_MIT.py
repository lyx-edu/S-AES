import tkinter as tk
from tkinter import messagebox

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
    return (S_BOX[nibble & 0x0F] << 4) | S_BOX[(nibble & 0xF0) >> 4]

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
    state = add_round_key(plaintext, (w[0] << 8) | w[1])  # 初始轮密钥加
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, (w[2] << 8) | w[3])  # 第二轮密钥加
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, (w[4] << 8) | w[5])  # 第三轮密钥加
    return state

# 解密函数
def s_aes_decrypt(ciphertext, key):
    w = key_expansion(key)
    state = add_round_key(ciphertext, (w[4] << 8) | w[5])  # 第三轮密钥加
    state = shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, (w[2] << 8) | w[3])  # 第二轮密钥加
    state = inv_mix_columns(state)
    state = shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, (w[0] << 8) | w[1])  # 初始轮密钥加
    return state

# 中间相遇攻击函数
def meet_in_the_middle_attack(plaintext, ciphertext):
    forward_map = {}
    possible_keys = []

    # 1. 计算前向加密表
    for K1 in range(0x0000, 0xFFFF + 1):  # 16位密钥的范围
        M1 = s_aes_encrypt(plaintext, K1)
        forward_map[M1] = K1

    # 2. 计算后向解密表
    for K2 in range(0x0000, 0xFFFF + 1):  # 16位密钥的范围
        M2 = s_aes_decrypt(ciphertext, K2)

        # 如果M2存在于前向加密表中，说明找到一个匹配的K1和K2
        if M2 in forward_map:
            K1 = forward_map[M2]
            possible_keys.append((K1, K2))

    # 3. 返回找到的所有可能的K1和K2组合
    return possible_keys

# Tkinter GUI
def attack():
    try:
        plaintext = int(entry_plaintext.get(), 2)
        ciphertext = int(entry_ciphertext.get(), 2)

        if plaintext < 0 or plaintext > 0xFFFF or ciphertext < 0 or ciphertext > 0xFFFF:
            raise ValueError("明文和密文必须是16位二进制数。")

        keys = meet_in_the_middle_attack(plaintext, ciphertext)

        # 清空文本框
        entry_key.delete('1.0', tk.END)  # 使用 '1.0' 来删除 Text 组件的内容
        if keys:
            for K1, K2 in keys:
                entry_key.insert(tk.END, f"K1: {format(K1, '016b')} K2: {format(K2, '016b')}\n")
        else:
            entry_key.insert(tk.END, "未找到匹配的密钥。")
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))

import tkinter as tk

# 定义攻击解密的函数（需实现该函数）
def attack():
    # 攻击解密逻辑在这里实现
    entry_key.delete(1.0, tk.END)  # 清空文本框
    entry_key.insert(tk.END, "密钥对结果将在此显示")  # 示例文本

# 创建主窗口
root = tk.Tk()
root.title("S-AES 中间相遇攻击解密")
root.geometry("500x300")
root.resizable(False, False)

# 明文输入
tk.Label(root, text="输入明文 (16bit):", font=("Helvetica", 10, "bold")).grid(row=1, column=0, padx=10, pady=5, sticky='e')
entry_plaintext = tk.Entry(root, width=30)
entry_plaintext.grid(row=1, column=1, padx=10, pady=5)

# 密文输入
tk.Label(root, text="输入密文 (16bit):", font=("Helvetica", 10, "bold")).grid(row=2, column=0, padx=10, pady=5, sticky='e')
entry_ciphertext = tk.Entry(root, width=30)
entry_ciphertext.grid(row=2, column=1, padx=10, pady=5)

# 攻击解密按钮
attack_button = tk.Button(root, text="攻击解密", command=attack, width=20)
attack_button.grid(row=3, column=0, columnspan=2, pady=15)

# 密钥对显示
tk.Label(root, text="密钥对:", font=("Helvetica", 10, "bold")).grid(row=4, column=0, padx=10, pady=(5, 5), sticky='ne')
entry_key = tk.Text(root, height=8, width=50, wrap="word")
entry_key.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

# 运行主循环
root.mainloop()

