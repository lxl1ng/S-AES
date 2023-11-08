import numpy as np

from key import *


# 双重加密
def double_aes_encrypt(text, key):
    key1 = key[:16]
    key2 = key[16:]
    text1 = encrypt(text, key1, '16')
    result = encrypt(text1, key2, '16')
    return result


# 双重解密
def double_aes_decrypt(text, key):
    key1 = key[:16]
    key2 = key[16:]
    text1 = decrypt(text, key2, '16')
    result = decrypt(text1, key1, '16')
    return result


# result = double_aes_encrypt('0000111111110001', '00000000000011110000000000000011')
# print('二重加密结果：'+result)
# result = double_aes_decrypt(result, '00000000000011110000000000000011')
# print('二重解密结果：'+result)


# 三重加密
def tripling_aes_encrypt(text, key):
    key1 = key[:16]
    key2 = key[16:32]
    key3 = key[32:]
    text1 = encrypt(text, key1, '16')
    text2 = encrypt(text1, key2, '16')
    result = encrypt(text2, key3, '16')
    return result


# 三重解密
def tripling_aes_decrypt(text, key):
    key1 = key[:16]
    key2 = key[16:32]
    key3 = key[32:]
    text1 = decrypt(text, key3, '16')
    text2 = decrypt(text1, key2, '16')
    result = decrypt(text2, key1, '16')
    return result


# result = tripling_aes_encrypt('0000111111110001', '000000000000111100000000000000110000000000001111')
# print('三重加密结果：'+result)
# result = tripling_aes_decrypt(result, '000000000000111100000000000000110000000000001111')
# print('三重加密解果：'+result)

# # 中间相遇攻击
# key1：1111000011110000
# 明文: 0000111111110001
# key2：0000111100001111
# 明文: 1000100111001000
# 密文：0001110000001110

# key1： 0000000000001111
# 明文: 0000111111110001
# key2： 0000000000000011
# 明文: 0011000111100101
# 密文：1111011101001011
plaintext = '0000111111110001'
ciphertext = '1111011101001011'
#
#
def middle_attack(plaintext, ciphertext):
    i = 0
    while i >= 0:
        key = bin(i)[2:].zfill(32)
        key1 = key[:16]
        key2 = key[16:]
        i += 1
        x1 = encrypt(plaintext, key1, '16')
        x2 = decrypt(ciphertext, key2, '16')
        if x1 == x2:
            print('次数为：' + str(i))
            print('值为：' + x1)
            print('key1:' + key1)
            print('key2:' + key2)


middle_attack(plaintext, ciphertext)


# CBC工作模式

# s 为待加密字符串，k 为伪随机数密钥
def xor_with_string(x_1, x_2):
    x = (int(x_1, 2) ^ int(x_2, 2))
    return f'{x:08b}'


def rondom_iv():
    iv_p = np.random.randint(0, 2, size=16)
    iv = ''
    for i in range(0, len(iv_p)):
        iv += str(iv_p[i])
    return iv


iv = '1001100000111111'
print('iv:' + iv)


def CBC_work_encrypt(plaintext, key):
    # 将明文分组
    plaintext_blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
    # 初始化密文列表
    ciphertext_blocks = []
    ciphertext = ''
    iv_key = xor_with_string(plaintext_blocks[0], iv)
    iv_key = str(iv_key).zfill(16)
    ciphertext_blocks.append(encrypt(iv_key, key, '16'))
    ciphertext = ciphertext + ciphertext_blocks[0]
    for i in range(len(plaintext_blocks)):
        if i != 0:
            iv_key = xor_with_string(ciphertext_blocks[i - 1], plaintext_blocks[i])
            iv_key = str(iv_key).zfill(16)
            ciphertext_blocks.append(encrypt(iv_key, key, '16'))
            ciphertext = ciphertext + ciphertext_blocks[i]
    print('加密总结果：' + ciphertext)
    return ciphertext


def CBC_work_decrypt(ciphertext, key):
    # 将密文分组
    ciphertext_blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    # 初始化密文列表
    plaintext_blocks = []
    plaintext = ''
    iv_key = decrypt(ciphertext_blocks[0], key, '16')
    plaintext_blocks.append((xor_with_string(iv, iv_key)).zfill(16))
    plaintext = plaintext + plaintext_blocks[0]
    for i in range(len(ciphertext_blocks)):
        if i != 0:
            iv_key = decrypt(ciphertext_blocks[i], key, '16')
            plaintext_blocks.append((xor_with_string(ciphertext_blocks[i - 1], iv_key)).zfill(16))
            plaintext = plaintext + plaintext_blocks[i]
    print('解密总结果：' + plaintext)
    return plaintext


# CBC_work_encrypt('000000000000111100000000000000110000000000001111', '1111000011110000')
# CBC_work_decrypt('010111100001001001100111110011110111010101111100', '1111000011110000')
