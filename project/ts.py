import tkinter as tk

root = tk.Tk()
root.title('S-AES')
root.geometry('750x600+600+300')

v = tk.IntVar()
v.set(1)

tk.Radiobutton(root, text="16进制模式", variable=v, value=1).pack(anchor="w")
tk.Radiobutton(root, text="Ascii模式", variable=v, value=2).pack(anchor="w")

root.mainloop()
