import tkinter as tk
from tkinter.messagebox import showerror

from PIL.ImageTk import PhotoImage

from ts import *


# 生成随机密钥
def rondom_key():
    type = v.get()
    print(type)
    while len(e0.get()) > 0:
        e0.delete(0)
    i = 0
    # 生成16位数组
    if type == 1:
        key = np.random.randint(0, 2, size=16)
        key_show = ''.join(str(i) for i in key)
        for char in key_show:
            # 获取每个字符并插入密钥框
            char = key_show[i]
            e0.insert(i, char)
            i += 1
    if type == 2:
        key = np.random.randint(0, 2, size=16)
        key_show = ''.join(str(i) for i in key)
        for char in key_show:
            # 获取每个字符并插入密钥框
            char = key_show[i]
            e0.insert(i, char)
            i += 1
    if type == 3:
        key = np.random.randint(0, 2, size=16)
        key_show = ''.join(str(i) for i in key)
        for char in key_show:
            # 获取每个字符并插入密钥框
            char = key_show[i]
            e0.insert(i, char)
            i += 1
    if type == 4:
        key = np.random.randint(0, 2, size=32)
        key_show = ''.join(str(i) for i in key)
        for char in key_show:
            # 获取每个字符并插入密钥框
            char = key_show[i]
            e0.insert(i, char)
            i += 1
    if type == 5:
        key = np.random.randint(0, 2, size=48)
        key_show = ''.join(str(i) for i in key)
        for char in key_show:
            # 获取每个字符并插入密钥框
            char = key_show[i]
            e0.insert(i, char)
            i += 1


# 加密按钮函数
def bind_encrypt():
    e2.delete(0, tk.END)
    key = e0.get()
    type = v.get()
    if type == 1:
        if len(key) != 16:
            result = showerror('错误', '密钥应是16位！')
            print(f'错误: {result}')
        else:
            text = e1.get()
            ciphertext = encrypt(text, key, '16')
            e2.insert(0, ciphertext)
    if type == 2:
        if len(key) != 16:
            result = showerror('错误', '密钥应是16位！')
            print(f'错误: {result}')
        else:
            text = e1.get()
            ciphertext = encrypt(text, key, 'ascii')
            e2.insert(0, ciphertext)
    if type == 3:
        if len(key) != 16:
            result = showerror('错误', '密钥应是16位！')
            print(f'错误: {result}')
        else:
            text = e1.get()
            ciphertext = CBC_work_encrypt(text, key)
            e2.insert(0, ciphertext)
    if type == 4:
        if len(key) != 32:
            result = showerror('错误', '密钥应是32位！')
            print(f'错误: {result}')
        else:
            text = e1.get()
            ciphertext = double_aes_encrypt(text, key)
            e2.insert(0, ciphertext)
    if type == 5:
        if len(key) != 48:
            result = showerror('错误', '密钥应是48位！')
            print(f'错误: {result}')
        else:
            text = e1.get()
            ciphertext = tripling_aes_encrypt(text, key)
            e2.insert(0, ciphertext)


# 解密按钮函数
def bind_decrypt():
    e4.delete(0, tk.END)
    key = e0.get()
    type = v.get()
    if type == 1:
        if len(key) != 16:
            result = showerror('错误', '密钥应是16位！')
            print(f'错误: {result}')
        else:
            text = e3.get()
            plaintext = decrypt(text, key, '16')
            e4.insert(0, plaintext)
    if type == 2:
        if len(key) != 16:
            result = showerror('错误', '密钥应是16位！')
            print(f'错误: {result}')
        else:
            text = e3.get()
            plaintext = decrypt(text, key, 'ascii')
            e4.insert(0, plaintext)
    if type ==3:
        if len(key) != 16:
            result = showerror('错误', '密钥应是16位！')
            print(f'错误: {result}')
        else:
            text = e3.get()
            plaintext = CBC_work_decrypt(text, key)
            e4.insert(0, plaintext)
    if type == 4:
        if len(key) != 32:
            result = showerror('错误', '密钥应是32位！')
            print(f'错误: {result}')
        else:
            text = e3.get()
            ciphertext = double_aes_decrypt(text, key)
            e4.insert(0, ciphertext)
    if type == 5:
        if len(key) != 48:
            result = showerror('错误', '密钥应是48位！')
            print(f'错误: {result}')
        else:
            text = e3.get()
            ciphertext = tripling_aes_decrypt(text, key)
            e4.insert(0, ciphertext)


# 控制密钥输入只能为0、1
def validate_binary_input(char, input_value):
    return char in '01'


# 基于tk生成的GUI界面
root = tk.Tk()
root.title('S-AES')
root.geometry('750x600+600+300')

# 加载背景图片
bg_image = PhotoImage(file="bg.jpg")
bg_label = tk.Label(root, image=bg_image)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)

v = tk.IntVar()
v.set(1)

tk.Radiobutton(root, text="16进制模式", variable=v, value=1, width=20, height=1).pack(anchor="w")
tk.Radiobutton(root, text="Ascii模式  ", variable=v, value=2, width=20, height=1).pack(anchor="w")
tk.Radiobutton(root, text="CBC工作模式  ", variable=v, value=3, width=20, height=1).pack(anchor="w")
tk.Radiobutton(root, text="双重加密模式  ", variable=v, value=4, width=20, height=1).pack(anchor="w")
tk.Radiobutton(root, text="三重加密模式  ", variable=v, value=5, width=20, height=1).pack(anchor="w")

# 密钥部分
key_validator = root.register(validate_binary_input)
tk.Label(root, text="密钥：", bg="white", fg='#7f7f7f').place(x=270, y=40)
e0 = tk.Entry(root, validate="key", validatecommand=(key_validator, "%S", "%P"), foreground='#000000')
e0.place(x=310, y=40)
tk.Button(root, text='随机生成!', command=rondom_key).place(x=350, y=70)

# 加密部分
tk.Label(root, text="明文：", bg="white", fg='#7f7f7f').place(x=30, y=170)
e1 = tk.Entry(root)
e1.place(x=77, y=170, width=220)
tk.Label(root, text="------------------------>", bg="black", fg='#7f7f7f').place(x=300, y=170)
tk.Label(root, text="密文：", bg="white", fg='#7f7f7f').place(x=437, y=170)
e2 = tk.Entry(root)
e2.place(x=484, y=170, width=220)
tk.Button(root, text='加密!', command=bind_encrypt).place(x=357, y=200)

# 解密部分
tk.Label(root, text="密文：", bg="white", fg='#7f7f7f').place(x=30, y=270)
e3 = tk.Entry(root)
e3.place(x=77, y=270, width=220)
tk.Label(root, text="------------------------>", bg="black", fg='#7f7f7f').place(x=300, y=270)
tk.Label(root, text="明文：", bg="white", fg='#7f7f7f').place(x=437, y=270)
e4 = tk.Entry(root)
e4.place(x=484, y=270, width=220)
tk.Button(root, text='解密!', command=bind_decrypt).place(x=357, y=300)

# 保持窗口存在
root.mainloop()
