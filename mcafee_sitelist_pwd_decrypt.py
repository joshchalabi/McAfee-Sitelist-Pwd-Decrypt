#!/usr/bin/env python3
# Info:
#   McAfee Sitelist.xml password decryption tool
#   Jerome Nokin (@funoverip) - Feb 2016
#   More info on https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
#   Updated for Python 3 compatibility.
#
# Quick howto:
#   Search for the XML element <Password Encrypted="1">...</Password>,
#   and paste the content as argument.
#
###########################################################################

import sys
import base64
from Crypto.Cipher import DES3
from Crypto.Hash import SHA

# hardcoded XOR key
# HATA DÜZELTMESİ: Python 2'deki .decode("hex") metodu Python 3'te kaldırıldı.
# Yerine bytes.fromhex() kullanılıyor.
KEY = bytes.fromhex("12150F10111C1A060A1F1B1817160519")

def sitelist_xor(data_bytes):
    """Girdi olarak verilen byte dizisini hardcoded KEY ile XOR'lar."""
    # HATA DÜZELTMESİ: Python 3'te baytlar üzerinde işlem yapmak için
    # girdinin ve anahtarın 'bytes' tipinde olduğundan emin olunmalıdır.
    # Sonuç da bir 'bytes' nesnesi olmalıdır.
    return bytes([b ^ KEY[i % 16] for i, b in enumerate(data_bytes)])

def des3_ecb_decrypt(data_bytes):
    """Verilen byte dizisini 3DES ECB kullanarak çözer."""
    # hardcoded 3DES key
    # HATA DÜZELTMESİ: .digest() bir bytes nesnesi döndürür.
    # Birleştirme işleminin de bir bytes nesnesi ile yapılması gerekir (b"..." notasyonu).
    key = SHA.new(b'<!@#$%^>').digest() + b"\x00\x00\x00\x00"

    # Şifreleme nesnesini oluştur ve şifreyi çöz
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_bytes = cipher.decrypt(data_bytes)

    # Padding'i (dolgu baytlarını) temizlemek için basit bir yöntem.
    # Genellikle şifrelenmiş metnin sonunda null byte (\x00) bulunur.
    padding_pos = decrypted_bytes.find(b'\x00')
    if padding_pos != -1:
        unpadded_bytes = decrypted_bytes[:padding_pos]
    else:
        # Eğer null byte bulunamazsa, tüm bloğun şifre olduğunu varsayalım.
        unpadded_bytes = decrypted_bytes

    # Son byte dizisini string'e çevir. Olası hataları önlemek için 'latin-1' kullanılır.
    # Eğer sonuç boşsa "<empty>" döndürülür.
    return unpadded_bytes.decode('latin-1') or "<empty>"


if __name__ == "__main__":

    if len(sys.argv) != 2:
        # Daha modern bir yazdırma formatı olan f-string'ler kullanıldı.
        print(f"Usage:   {sys.argv[0]} <base64 passwd>")
        print(f"Example: {sys.argv[0]} 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='")
        sys.exit(0)

    encrypted_password_b64 = sys.argv[1]

    try:
        # Base64 string'ini byte'a çevir
        encrypted_password_bytes = base64.b64decode(encrypted_password_b64)

        # Byte'ları XOR'la
        xored_bytes = sitelist_xor(encrypted_password_bytes)

        # Sonucu deşifrele
        password = des3_ecb_decrypt(xored_bytes)

        # Sonuçları yazdır
        print(f"Crypted password   : {encrypted_password_b64}")
        print(f"Decrypted password : {password}")

    except base64.binascii.Error as e:
        print(f"Error: Invalid base64 input. {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0)
