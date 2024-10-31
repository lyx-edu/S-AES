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
    return ( S_BOX[nibble & 0x0F]<< 4) | S_BOX[(nibble & 0xF0) >> 4]

# 字节替代函数
def sub_bytes(state):
    return (
        (S_BOX[(state & 0xF000) >> 12] << 12) |  # 处理高 4 位
        (S_BOX[(state & 0x0F00) >> 8] << 8) |    # 处理次高 4 位
        (S_BOX[(state & 0x00F0) >> 4] << 4) |    # 处理次低 4 位
        (S_BOX[state & 0x000F])                   # 处理低 4 位
    )

# 逆字节替代函数
def inv_sub_bytes(state):
    return (
        (INV_S_BOX[(state & 0xF000) >> 12] << 12) |  # 处理高 4 位
        (INV_S_BOX[(state & 0x0F00) >> 8] << 8) |    # 处理次高 4 位
        (INV_S_BOX[(state & 0x00F0) >> 4] << 4) |    # 处理次低 4 位
        (INV_S_BOX[state & 0x000F])                   # 处理低 4 位
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
# GF(2^4) 下乘 9
def mul9(nibble):
    # 乘以 4 再乘 2 ，最后加上原始 nibble
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

# Tkinter GUI
def encrypt():
    try:
        plaintext = int(entry_plaintext.get(), 2)
        key = int(entry_key.get(), 2)
        if plaintext < 0 or plaintext > 0xFFFF or key < 0 or key > 0xFFFF:
            raise ValueError("明文和密钥必须是16位二进制数。")
        ciphertext = s_aes_encrypt(plaintext, key)
        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(tk.END, format(ciphertext, '016b'))
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))

def decrypt():
    try:
        ciphertext = int(entry_ciphertext.get(), 2)
        key = int(entry_key.get(), 2)
        if ciphertext < 0 or ciphertext > 0xFFFF or key < 0 or key > 0xFFFF:
            raise ValueError("密文和密钥必须是16位二进制数。")
        plaintext = s_aes_decrypt(ciphertext, key)
        entry_plaintext.delete(0, tk.END)
        entry_plaintext.insert(tk.END, format(plaintext, '016b'))
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))


# ASCII与二进制的转换辅助函数

def text_to_binary(text):
    # 将文本转换为16位整数列表（每2个字符为1块）
    binary_data = []
    for i in range(0, len(text), 2):
        block = text[i:i+2]
        # 如果不足2个字符则填充
        if len(block) == 1:
            block += '\0'
        binary_data.append((ord(block[0]) << 8) + ord(block[1]))
    return binary_data

def binary_to_text(binary_data):
    # 将16位整数列表转换回ASCII文本
    text = ""
    for block in binary_data:
        text += chr((block >> 8) & 0xFF) + chr(block & 0xFF)
    return text

# 新增ASCII的加密解密函数

def ascii_encrypt():
    try:
        plaintext = entry_plaintext.get()
        key = int(entry_key.get(), 2)
        if key < 0 or key > 0xFFFF:
            raise ValueError("密钥必须是16位二进制数。")

        binary_data = text_to_binary(plaintext)
        encrypted_blocks = [s_aes_encrypt(block, key) for block in binary_data]

        # 将加密后的块转换为ASCII文本（可能显示为乱码）
        ciphertext = binary_to_text(encrypted_blocks)
        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(tk.END, ciphertext)
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))

def ascii_decrypt():
    try:
        ciphertext = entry_ciphertext.get()
        key = int(entry_key.get(), 2)
        if key < 0 or key > 0xFFFF:
            raise ValueError("密钥必须是16位二进制数。")

        binary_data = text_to_binary(ciphertext)
        decrypted_blocks = [s_aes_decrypt(block, key) for block in binary_data]

        # 将解密后的块转换回可读的ASCII文本
        plaintext = binary_to_text(decrypted_blocks)
        entry_plaintext.delete(0, tk.END)
        entry_plaintext.insert(tk.END, plaintext.strip('\x00'))  # 移除填充的空字符
    except ValueError as e:
        messagebox.showerror("输入错误", str(e))



# 创建主窗口
root = tk.Tk()
root.title("S-AES 加密解密")
root.geometry("400x300")
root.resizable(False, False)

# 明文、密钥输入和加密、解密按钮
tk.Label(root, text="输入明文 (16bit):", font=("Helvetica", 10, "bold")).grid(row=1, column=0, padx=10, pady=5, sticky='e')
entry_plaintext = tk.Entry(root, width=25)
entry_plaintext.grid(row=1, column=1, padx=10, pady=5)

tk.Label(root, text="输入密钥 (16bit):", font=("Helvetica", 10, "bold")).grid(row=2, column=0, padx=10, pady=5, sticky='e')
entry_key = tk.Entry(root, width=25)
entry_key.grid(row=2, column=1, padx=10, pady=5)

# 普通加密和解密按钮
tk.Button(root, text="加密", command=encrypt, width=12).grid(row=3, column=0, padx=10, pady=5)
tk.Button(root, text="解密", command=decrypt, width=12).grid(row=3, column=1, padx=10, pady=5)

# ASCII 加密和解密按钮
tk.Button(root, text="ASCII 加密", command=ascii_encrypt, width=12).grid(row=4, column=0, padx=10, pady=5)
tk.Button(root, text="ASCII 解密", command=ascii_decrypt, width=12).grid(row=4, column=1, padx=10, pady=5)

# 密文输出
tk.Label(root, text="密文 (16bit):", font=("Helvetica", 10, "bold")).grid(row=5, column=0, padx=10, pady=5, sticky='e')
entry_ciphertext = tk.Entry(root, width=25)
entry_ciphertext.grid(row=5, column=1, padx=10, pady=5)

root.mainloop()
