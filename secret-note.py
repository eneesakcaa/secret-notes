from tkinter import *
from tkinter import messagebox
import pybase64
import base64


window = Tk()
window.title("secret note")
window.minsize(width = 300,height=500)
window.config(bg="white")

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = enter_title.get()
    message = my_text.get("1.0",END)
    password = enter_key.get()

    if len(title) == 0 or len(message) == 0 or len(password) ==0:
        messagebox.showwarning(title="ERROR!!!",message="PLEASE ENTER ALL İNFO")

    else:
        message_encrypted = encode(password, message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n {title}\n {message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n {title}\n {message_encrypted}")   

        finally:
            enter_title.delete(0,END)
            my_text.delete("1.0",END)
            enter_key.delete(0,END)


def decrypt_notes():
    message_encrypted = my_text.get("1.0",END)
    master_secret = enter_key.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showwarning(title="ERROR!!!",message="PLEASE ENTER ALL İNFO")
    else:
        try:
            decrypted_message = decode(master_secret, message_encrypted)
            my_text.delete("1.0",END)
            my_text.insert("1.0", decrypted_message)

        except:
               messagebox.showwarning(title="ERROR",message="PLEASE ENTER ENCRYPTED TEXT!")

enter_your_title = Label(text="Enter Your Title")
enter_your_title.pack()
enter_title = Entry(bg="white")
enter_title.pack(pady=5)
enter_your_secret = Label(text="Enter Your Secret")
enter_your_secret.pack()
my_text = Text(bg="white",width=16,height=10)
my_text.pack(pady=5)
enter_master_key = Label(text="Enter Password")
enter_master_key.pack()
enter_key = Entry(bg="white", width=22, show="*")
enter_key.pack(pady=5)
save_button = Button(text="save & encrypt",command= save_and_encrypt)
save_button.pack()
decrypt_button = Button(text="decrypt",command=decrypt_notes)
decrypt_button.pack()
window.mainloop()