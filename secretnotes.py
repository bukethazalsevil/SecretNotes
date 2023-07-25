from tkinter import *
from tkinter import messagebox
import base64

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

def saveAndEncrypt():
    saveTitle = entryTitle.get()
    saveText = message.get("1.0" , END)
    savePassword = passwordEntry.get()

    if saveTitle == "" or saveText == "" or savePassword == "":
        messagebox.showerror(title="ERROR!" , message="Please fill the blanks")

    else:
        encryptedMessage = encode(savePassword,saveText)

        try:
            with open("secretnote.txt" , "a") as dataFile:
                dataFile.write(f"\n{saveTitle}\n{encryptedMessage}")
        except FileNotFoundError:
            with open("secretnote.txt" , "w") as dataFile:
                dataFile.write(f"\n{saveTitle}\n{encryptedMessage}")

        finally:
            entryTitle.delete(0,END)
            message.delete("1.0",END)
            passwordEntry.delete("1.0",END)

def decryptNote():
    encryptedMessage = message.get("1.0" , END)
    savePassword = passwordEntry.get()

    if encryptedMessage == "" or savePassword == "":
        messagebox.showerror(title="ERROR!", message="Please fill the blanks")
    else:
        try:
            decryptedNote = decode(savePassword,encryptedMessage)
            message.delete("1.0" , END)
            message.insert("1.0",decryptedNote)
        except:
            messagebox.showerror(title="ERROR!" , message="Please check again")









window = Tk()
window.title("Secret Notes")
window.config(padx=40, pady=40 )

photo = PhotoImage(file="topsecret.png")
photoLabel = Label(image=photo , background="white")
photoLabel.pack()

titleLabel = Label(text="Enter Your Title")
titleLabel.pack()
entryTitle = Entry()
entryTitle.pack()

message = Text()
message.pack()

passwordLabel = Label(text="Enter password")
passwordLabel.pack()
passwordEntry = Entry()
passwordEntry.pack()

encryptSaveButton = Button(text="Save & Encrypt" , command=saveAndEncrypt)
encryptSaveButton.pack()

decryptButton = Button(text="Decrypt" , command=decryptNote)
decryptButton.pack()


window.mainloop()