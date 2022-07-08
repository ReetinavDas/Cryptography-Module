# -*- coding: utf-8 -*-
"""
Created on Thu Jul  7 00:46:28 2022

@author: Reetinav Das
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def AESencrypt(file, password = b""):
#here we are making sure that the password is of type byte and that it is the correct amount of characters

    if (len(password) > 32):
        raise ValueError("Password size is too long, the max is 32 characters.")
    
    if (password == b""):
        password = get_random_bytes(32) 
    
    if (len(password) < 32 and type(password == str)):#this will add padding to a given password until the length of the password is 32
        password = password.ljust(32, "*")
        password = password.encode()
    #we can now start the encryption process  
    cipher = AES.new(password, AES.MODE_EAX)
    with open(file, 'rb') as file_read:
        original = file_read.read() 
    ciphertext, tag = cipher.encrypt_and_digest(original)
    with open(file, 'wb') as file_enc:
        [file_enc.write(x) for x in (cipher.nonce, tag, ciphertext)    ]    
    
    return ciphertext

def AESdecrypt(file, password = b""):
    #here we are making sure that the password is of type byte and that it is the correct amount of characters

    if (len(password) > 32):
        raise ValueError("Password size is too long, the max is 32 characters.")
    
    if (password == b""):
        password = get_random_bytes(32) 
    
    if (len(password) < 32 and type(password == str)):#this will add padding to a given password until the length of the password is 32
        password = password.ljust(32, "*")
        password = password.encode()
        
   #We can now start the decryption process
    
    with open(file, 'rb') as file_enc:
        nonce, tag, ciphertext = [file_enc.read(x) for x in [16,16,-1]]
    cipher = AES.new(password, AES.MODE_EAX, nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)  
    
    with open(file, 'wb') as file_dec:
       file_dec.write(decrypted)
        
    return decrypted
        
print(AESencrypt(r'C:\Users\Test\Downloads\HW3.pdf', password = "Vaniteer"))
print(AESdecrypt(r'C:\Users\Test\Downloads\HW3.pdf', password = "Vaniteer"))

