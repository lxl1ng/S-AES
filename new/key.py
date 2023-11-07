# 定义S盒和逆S盒
S_box = [
    ['9', '4', 'A', 'B'],
    ['D', '1', '8', '5'],
    ['6', '2', '0', '3'],
    ['C', 'E', 'F', '7']
]

inverse_S_box = [
    ['A', '5', '9', 'B'],
    ['1', '7', '8', 'F'],
    ['6', '0', '2', '3'],
    ['C', '4', 'D', 'E']
]

# 定义轮常量
round_constants = ['01', '02', '04', '08', '10', '20', '40', '80', '1B', '36']


# 半字节代替函数
def subnib(char):
    row = int(char[0]) * 2 + int(char[1])
    col = int(char[2]) * 2 + int(char[3])
    return hex_to_bin(S_box[row][col])


def inverse_subnib(char):
    row = int(char[0]) * 2 + int(char[1])
    col = int(char[2]) * 2 + int(char[3])
    return hex_to_bin(inverse_S_box[row][col])


# ansi_x923填充
def ansi_x923_pad(text, block_size):
    text = text.encode('utf-8')
    pad_size = (block_size - (len(text) % block_size)) % block_size
    if pad_size != 0:
        for _ in range(pad_size - 1):
            text += b'0'
        text += str(pad_size).encode('utf-8')
    return text


def ansi_x923_unpad(text):
    if text[-1].isdigit():
        pad_size = int(text[-1])
        if 0 < int(text[-1]) < 4:
            for i in range(pad_size - 1):
                if int(text[-i - 2]) != 0:
                    return text
            return text[:-pad_size]
        else:
            return text
    else:
        return text


# 将16进制字符转换为二进制字符串
def hex_to_bin(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(4)


# 将ascii码转换为16进制字符
def ascii_to_hex(ascii_value):
    binary_value = format(ascii_value, '08b')
    return bin_to_hex(binary_value[:4]) + bin_to_hex(binary_value[4:])


# 将16进制字符转换为ascii码
def hex_to_ascii(hex_value):
    decimal_value = int(hex_value, 16)
    ascii_char = chr(decimal_value)
    return ascii_char


# 将二进制字符串转换为16进制字符
def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].upper()


# 将10进制字符串转换为2进制字符
def decimal_to_binary(decimal_number, n):
    return bin(decimal_number)[2:].zfill(n)


# 密钥加
def xor(list1, list2):
    result = []
    for i in range(len(list1)):
        row_result = []
        for j in range(len(list1[i])):
            xor_result = decimal_to_binary(int(list1[i][j], 2) ^ int(list2[i][j], 2), 4)
            row_result.append(xor_result)
        result.append(row_result)
    return result


# 密钥扩展
def expand_key(key):
    RC = [0b10000000, 0b00110000]
    round_keys = [key[i:i + 8] for i in range(0, len(key), 8)]
    for i in range(2):
        pp_key = int(round_keys[-2], 2)
        prev_key = round_keys[-1][4:] + round_keys[-1][:4]
        first = S_box[int(prev_key[0]) * 2 + int(prev_key[1])][int(prev_key[2]) * 2 + int(prev_key[3])]
        last = S_box[int(prev_key[4]) * 2 + int(prev_key[5])][int(prev_key[6]) * 2 + int(prev_key[7])]
        sub = int(hex_to_bin(first) + hex_to_bin(last), 2)
        round_keys.append(decimal_to_binary(pp_key ^ RC[i] ^ sub, 8))
        round_keys.append(decimal_to_binary(int(round_keys[-1], 2) ^ int(round_keys[-2], 2), 8))
    return round_keys


# gf乘法
def gf_multiply(a, b):
    result = 0
    while b > 0:
        if b & 1 == 1:
            result ^= a
        a <<= 1
        b >>= 1
        if len(bin(result)[2:]) > 4:
            mo = 19 << (len(bin(result)[2:]) - 5)
            result ^= mo
    return result % 16  # 结果要在0到15之间


# AES加密函数
def aes_encrypt(plaintext, key):
    round_key = expand_key(key)
    ciphertext = ''
    s_key = [[[round_key[j * 2][4 * i:4 * i + 4], round_key[j * 2 + 1][4 * i:4 * i + 4]] for i in range(2)] for j in
             range(3)]
    for i in range(0, len(plaintext), 4):
        text = plaintext[i:i + 4].decode('utf-8')
        # 初始矩阵
        S = [[hex_to_bin(str(text[i])), hex_to_bin(str(text[i + 2]))] for i in range(2)]
        # 密钥加
        text = xor(S, s_key[0])
        # 半字节替代
        text = [[subnib(text[j][i]) for i in range(2)] for j in range(2)]
        # 行位移
        text[1][0], text[1][1] = text[1][1], text[1][0]
        # 列混淆
        text = [[int(text[0][0], 2) ^ gf_multiply(4, int(text[1][0], 2)),
                 int(text[0][1], 2) ^ gf_multiply(4, int(text[1][1], 2))],
                [int(text[1][0], 2) ^ gf_multiply(4, int(text[0][0], 2)),
                 int(text[1][1], 2) ^ gf_multiply(4, int(text[0][1], 2))]]
        text = [[decimal_to_binary(text[j][i], 4) for i in range(2)] for j in range(2)]
        # 密钥加
        text = xor(text, s_key[1])
        # 半字节替代
        text = [[subnib(text[j][i]) for i in range(2)] for j in range(2)]
        # 行位移
        text[1][0], text[1][1] = text[1][1], text[1][0]
        # 密钥加
        text = xor(text, s_key[2])
        # 输出密文
        for i in range(2):
            for j in range(2):
                ciphertext += bin_to_hex(text[j][i])
    return ciphertext.encode('utf-8')


# AES解密函数
def aes_decrypt(ciphertext, key):
    plaintext = ''
    round_key = expand_key(key)
    s_key = [[[round_key[j * 2][4 * i:4 * i + 4], round_key[j * 2 + 1][4 * i:4 * i + 4]] for i in range(2)] for j in
             range(3)]
    for i in range(0, len(ciphertext), 4):
        text = ciphertext[i:i + 4]
        # 初始矩阵
        S = [[hex_to_bin(str(text[i])), hex_to_bin(str(text[i + 2]))] for i in range(2)]
        # 密钥加
        text = xor(S, s_key[2])
        # 逆行位移
        text[1][0], text[1][1] = text[1][1], text[1][0]
        # 逆半字节替代
        text = [[inverse_subnib(text[j][i]) for i in range(2)] for j in range(2)]
        # 密钥加
        text = xor(text, s_key[1])
        # 逆列混淆
        text = [[gf_multiply(9, int(text[0][0], 2)) ^ gf_multiply(2, int(text[1][0], 2)),
                 gf_multiply(9, int(text[0][1], 2)) ^ gf_multiply(2, int(text[1][1], 2))],
                [gf_multiply(9, int(text[1][0], 2)) ^ gf_multiply(2, int(text[0][0], 2)),
                 gf_multiply(9, int(text[1][1], 2)) ^ gf_multiply(2, int(text[0][1], 2))]]
        text = [[decimal_to_binary(text[j][i], 4) for i in range(2)] for j in range(2)]
        # 逆行位移
        text[1][0], text[1][1] = text[1][1], text[1][0]
        # 逆半字节替代
        text = [[inverse_subnib(text[j][i]) for i in range(2)] for j in range(2)]
        # 逆密钥加
        text = xor(text, s_key[0])
        # 输出密文
        for i in range(2):
            for j in range(2):
                plaintext += bin_to_hex(text[j][i])
    return plaintext


def ades_process_data(text, key, type='ascii', mode='encrypt'):
    print(f'密钥： {key}')
    if mode == 'encrypt':
        print(f'明文: {text}')
        # print(ascii_to_hex(text))
        if type == 'ascii':
            plaintext_c = ansi_x923_pad(text, 2)
            data = ''
            for char in plaintext_c:
                data += ascii_to_hex(char)
            data = data.encode('utf-8')
            ciphertext = aes_encrypt(data, key)
            ciphertext = ciphertext.decode('utf-8')
            ciphertext = hex_to_ascii(ciphertext)
        else:
            text = bin_to_hex(text).zfill(4)
            data = ansi_x923_pad(text, 4)
            ciphertext = aes_encrypt(data, key)
            ciphertext = hex_to_bin(ciphertext.decode('utf-8')).zfill(16)
        print(f"加密后: {ciphertext}")
        return ciphertext
    else:
        print(f'密文: {text}')

        if type == 'ascii':
            detext = ''
            deciphertext = aes_decrypt(text, key)
            for i in range(0, len(deciphertext), 2):
                detext += hex_to_ascii(deciphertext[i:i + 2])
            if len(text) % 4 == 0:
                detext += '0'
                detext = ansi_x923_unpad(detext)
                detext = detext[:-1]
            else:
                detext = ansi_x923_unpad(detext)
        elif len(text) % 4 == 0:
            text = bin_to_hex(text).zfill(4)
            deciphertext = aes_decrypt(text, key)
            detext = deciphertext
            detext = hex_to_bin(detext).zfill(16)
        else:
            text = bin_to_hex(text).zfill(4)
            deciphertext = aes_decrypt(text, key)
            detext = ansi_x923_unpad(deciphertext)
            detext = hex_to_bin(detext).zfill(16)
        print(f'解密后: {detext}')
        return detext


# # 输入ascii明文进行加解密
# ades_process_data('31DF', '0100101011110101', 'ascii', 'encrypt')
print('!!!!!!!!!!!!!')
# # 输入16进制明文进行加解密
ades_process_data('1101011100101000', '0100101011110101', '16', 'encrypt')
ades_process_data('0010010011101100', '0100101011110101', '16', 'decrypt')
# ades_process_data('7BBF7BBFE8E9EBB9', '0010110101010101', '16', 'decrypt')
ades_process_data('p1', '0010110101010101', 'ascii', 'encrypt')
# print(hex_to_bin('0738').zfill(16))
# print(bin_to_hex('0000011100111000').zfill(4))
# ades_process_data('JA', '0010110101010101', 'ascii', 'decrypt')
# print((bin(ord('p'))[2:].zfill(8)))
