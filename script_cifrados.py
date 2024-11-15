from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def pad_key(key, algorithm):
    key_size = {
        'DES': 8,
        'AES-256': 32,
        '3DES': 24
    }[algorithm]
   
    if len(key) < key_size:
        return key + get_random_bytes(key_size - len(key))
    elif len(key) > key_size:
        return key[:key_size]
    else:
        return key

def encrypt_DES(key, iv, plaintext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_DES(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size).decode()
    return plaintext

def encrypt_AES256(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def decrypt_AES256(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext

def encrypt_3DES(key, iv, plaintext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_3DES(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES3.block_size).decode()
    return plaintext

# Solicitar datos al usuario
algorithm = input("Selecciona el algoritmo (DES, AES-256, 3DES): ")
key = input(f"Ingresa la clave ({algorithm}): ").encode()
iv = input(f"Ingresa el vector de inicialización (IV) ({algorithm}): ").encode()
plaintext = input("Ingresa el texto a cifrar: ")

# Ajustar la clave
key = pad_key(key, algorithm)
print(f"Clave final utilizada ({algorithm}): {key}")

# Cifrar y descifrar
if algorithm == 'DES':
    ciphertext = encrypt_DES(key, iv, plaintext)
    decrypted_text = decrypt_DES(key, iv, ciphertext)
elif algorithm == 'AES-256':
    ciphertext = encrypt_AES256(key, iv, plaintext)
    decrypted_text = decrypt_AES256(key, iv, ciphertext)
elif algorithm == '3DES':
    ciphertext = encrypt_3DES(key, iv, plaintext)
    decrypted_text = decrypt_3DES(key, iv, ciphertext)

print(f"Texto cifrado ({algorithm}): {ciphertext.hex()}")
print(f"Texto descifrado ({algorithm}): {decrypted_text}")
