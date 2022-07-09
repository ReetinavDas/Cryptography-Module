# -*- coding: utf-8 -*-
"""
Created on Thu Jul  7 00:46:28 2022

@author: Reetinav Das
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def AESencrypt(file, password = b""):
    """
    This function encrypts a file using AES 256

    Parameters
    ----------
    file : TYPE = str
        This is the file path.
    password : TYPE = str, optional
        The password that a user can input. If they choose not to, then we 
        generate a random password.

    Returns 
    -------
    password: This is only necessary if the user chooses not to input 
    their own password. In this case we return the password so they know what 
    their randomly generate password actually is.
    -------
    """
    #here we are making sure that the password is of type byte and that it is the correct amount of characters
    if (len(password) > 32):
        raise ValueError("Password size is too long, the max is 32 characters.")
    
    if (password == b""): #here we generate a random password if none was given
        password = get_random_bytes(32) 
    if (len(password) < 32 and type(password == str)):
        password = password.ljust(32, "*") #we add padding so the password length is 32
        password = password.encode()
   
    #we can now start the encryption process  
    cipher = AES.new(password, AES.MODE_EAX)
    with open(file, 'rb') as file_read:
        original = file_read.read() #storing contents of the file in original
    ciphertext, tag = cipher.encrypt_and_digest(original) #we encrypt the original plaintext
    with open(file, 'wb') as file_enc: #we write the encrypted contents to the file
        [file_enc.write(x) for x in (cipher.nonce, tag, ciphertext)]    
    
    return password #this is for those who chose not to use their own password

def AESdecrypt(file, password):
    """
    Parameters
    ----------
    file : TYPE = str
        This is the file path.
    password : str
         The password that the user has to input in order to decrypt the file.
    Returns
    -------
    None.
    """
    #here we are making sure that the password is of type byte and that it is the correct amount of characters

    if (len(password) > 32):
        raise ValueError("Password size is too long, the max is 32 characters.")
    
    if (len(password) < 32 and type(password == str)):
        password = password.ljust(32, "*") #we add padding so the password length is 32
        password = password.encode()
        
   #We can now start the decryption process  
    with open(file, 'rb') as file_enc:
        nonce, tag, ciphertext = [file_enc.read(x) for x in [16,16,-1]] #storing the contents of the encrypted file
    cipher = AES.new(password, AES.MODE_EAX, nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag) #we decrypt the encrypted contents
    
    with open(file, 'wb') as file_dec: #we write the decrypted contents to the file
       file_dec.write(decrypted)
        
    
#these are simply examples of using the functions; you'll want to replace the 
#filepath with one that works for you; make sure you put r before the filepath

#print(AESencrypt(r'C:\Users\Reetinav\Documents\file.txt', password = "Vaniteer"))
#print(AESdecrypt(r'C:\Users\Reetinav\Documents\file.txt', password = "Vaniteer"))
