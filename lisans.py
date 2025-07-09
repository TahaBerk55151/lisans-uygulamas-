import os, json, uuid, hashlib
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

LISANS_DOSYASI = "mac_liste.json"

def get_mac():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> bits) & 0xff) for bits in range(0, 2*6, 8)][::-1])

def generate_key(mac): return hashlib.sha256(mac.encode()).digest()

def mac_listesi_yukle():
    if not os.path.exists(LISANS_DOSYASI):
        with open(LISANS_DOSYASI, "w") as f: json.dump({"mac_adresleri": []}, f)
    with open(LISANS_DOSYASI, "r") as f:
        return json.load(f)["mac_adresleri"]

def mac_ekle(mac):
    maclar = mac_listesi_yukle()
    if mac not in maclar:
        maclar.append(mac)
        with open(LISANS_DOSYASI, "w") as f:
            json.dump({"mac_adresleri": maclar}, f, indent=2)
        return True
    return False

def mac_sil(mac):
    maclar = mac_listesi_yukle()
    if mac in maclar:
        maclar.remove(mac)
        with open(LISANS_DOSYASI, "w") as f:
            json.dump({"mac_adresleri": maclar}, f, indent=2)
        return True
    return False

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path: return
    maclar = mac_listesi_yukle()
    for mac in maclar:
        key = generate_key(mac)
        cipher = AES.new(key, AES.MODE_CBC)
        with open(file_path, 'rb') as f: data = f.read()
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        out_path = f"{file_path}_{mac.replace(':','')}.enc"
        with open(out_path, 'wb') as f: f.write(cipher.iv + encrypted_data)
    messagebox.showinfo("Şifreleme Başarılı", "Tüm lisanslı MAC adresleri için dosya şifrelendi.")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path: return
    mac = get_mac()
    maclar = mac_listesi_yukle()
    if mac not in maclar:
        messagebox.showerror("Erişim Reddedildi", "Bu cihaz lisanslı değil!")
        return
    try:
        key = generate_key(mac)
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            encrypted_data = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        out_path = file_path.replace(".enc", "") + "_cozuldu"
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
        messagebox.showinfo("Başarılı", f"Dosya çözüldü: {out_path}")
    except Exception as e:
        messagebox.showerror("Hata", str(e))

def mac_ekle_arayuz():
    mac = entry_mac.get().strip()
    if mac:
        if mac_ekle(mac):
            messagebox.showinfo("Ekleme Başarılı", f"{mac} eklendi.")
        else:
            messagebox.showinfo("Zaten Var", f"{mac} zaten listede.")
        entry_mac.delete(0, END)

def mac_sil_arayuz():
    mac = entry_mac.get().strip()
    if mac:
        if mac_sil(mac):
            messagebox.showinfo("Silme Başarılı", f"{mac} silindi.")
        else:
            messagebox.showinfo("Bulunamadı", f"{mac} listede yok.")
        entry_mac.delete(0, END)

### Arayüz ###
pencere = Tk()
pencere.title("🔐 Lisans Yönetimi")
pencere.geometry("400x400")
pencere.config(bg="#1e1e2f")

Label(pencere, text="MAC Adres:", bg="#1e1e2f", fg="white", font=("Segoe UI", 10)).pack(pady=5)
entry_mac = Entry(pencere, width=30)
entry_mac.pack(pady=5)

Button(pencere, text="MAC Ekle", command=mac_ekle_arayuz, bg="#0078D7", fg="white").pack(pady=2)
Button(pencere, text="MAC Sil", command=mac_sil_arayuz, bg="#D83B01", fg="white").pack(pady=2)

Frame(pencere, height=2, bd=1, relief=SUNKEN, bg="#ccc").pack(fill=X, padx=20, pady=10)

Button(pencere, text="Dosya Şifrele", command=encrypt_file, bg="#2d88ff", fg="white", width=25).pack(pady=10)
Button(pencere, text="Dosya Çöz", command=decrypt_file, bg="#107C10", fg="white", width=25).pack(pady=10)
Label(pencere, text=f"Aktif MAC: {get_mac()}", bg="#1e1e2f", fg="#a0a0a0").pack(pady=15)

pencere.mainloop()