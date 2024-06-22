from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from base64 import b64encode
from os import urandom
import hashlib

flag_hash = "6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e"

def decrypt():
    key = b'the_enc_key_is_'
    iv = b'my_great_iv_is_'
    key += urandom(1)
    iv += urandom(1)

    encrypted_flag = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'


    cipher = AES.new(key, AES.MODE_CBC, iv)
    FLAG = unpad(cipher.decrypt(encrypted_flag), 16)
    flag_hashs = hashlib.sha256(FLAG.decode('utf-8').encode('utf-8')).hexdigest()
   
    return iv, key, flag_hashs, FLAG.decode('utf-8')
        

while True:
    try:
        IV, KEY, HASH, FLAG = decrypt()
        if flag_hash == HASH:
            print(f"KEY: {KEY}\nIV: {IV}\nflag_hash: {HASH}\nFLAG: {FLAG}")
            break
 
    except (ValueError, KeyError):
        print("Incorrect padding!")
