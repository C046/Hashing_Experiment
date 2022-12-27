"""
Created on Sun Dec 25 19:30:36 2022

@author: hadaw
"""

import os
import glob
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


import numpy as np
import pandas as pd

class Hasher:
    def __init__(self, password, username):
        super().__init__()
        # Turn the username, password into bytes and generate a random salt.
        self.username,self.password,self.salt,self.key = (
            bytes(username.encode()),
            bytes(password.encode()),
            os.urandom(16),
            Fernet.generate_key(),
        
        )
        
        # Attempt to create a directory
        try:
            path = os.path.abspath("D:/InTheMoneyApplication/Hasher/Users")
            path1 = os.path.abspath("C:/InTheMoneyApplication/Hasher/Users")
            os.mkdir(path)
            
        except Exception as Error:
            
            #del Error
            if not FileExistsError:
                try:
                    os.mkdir(path1)
            
                except Exception as Error:
                    del Error
                
            del Error
    
    def _remove_usb(self):
        os.system("""diskpart /s E:/drive_letter.txt""")
        
    def _reconnect_usb(self):
        os.system("""diskpart /s F:/Reconnect_USB.txt""")
        
        
        
    # Create a function to create a KDF
    def _genKDF_(self):
        # Establish arguments.
        algorithm = hashes.SHA512_256()
        length = 32
        salt = self.salt
        iterations = 480000*10
        
        # Establish KDF.
        kdf = PBKDF2HMAC(
            algorithm,
            length,
            salt,
            iterations,
        )
        
        # Delete the arguments
        del algorithm,length,salt,iterations
        
        # Return the KDF
        return kdf
        
    def _encrypt(self, path):
        # Reconnect the usb
        self._reconnect_usb()
        # IF the directory exists delete the keys and hashes from previous use.
        if os.path.isdir("E:/Application_Keys/EncryptedHashes"):
            files = glob.glob("E:/Application_Keys/EncryptedHashes/*.txt",recursive=True)
            for f in files:
                try:
                    
                    os.remove(f)
            
                except OSError as Error:
                    del Error
            del files
            
        if os.path.isdir("E:/Application_Keys/encryption_keys"):
            files = glob.glob("E:/Application_Keys/encryption_keys/*.txt",recursive=True)
            
            for f in files:
                try:
                    
                    os.remove(f)
                    
                except OSError as Error:
                    del Error
        else:
                
             # IF the directories do not exist
             # create them all
             try:
                
                 os.mkdir("E:/Application_Keys")
                 os.mkdir("E:/Application_Keys/EncryptedHashes")
                 os.mkdir("E:/Application_Keys/encryption_keys")
            
             except Exception as Error:
                 # IF this fails that means there is no usb
                 # delete key, error, self.username, self.password
                 del Error, self.key,path, self.username,self.password
                
        try:
            # Open Filepath to encrypt
            with open(path, "rb") as _file:
                # Read the _file
                file_data = _file.read()
                _file.close()
                
        except Exception as Error:
            del Error
            
        try:
            # Create a Fernet object using the secret key    
            _file = Fernet(self.key)
            # Encrypt the file_data
            encrypted_data = _file.encrypt(file_data)
            
            
            # Create a new document
            with open(os.path.abspath(f"E:/Application_Keys/EncryptedHashes/encrypted_hashed_User-{np.random.randint(0,10000)}.txt"), "wb") as _file:
                _file.write(encrypted_data)
                _file.close()
                
        except Exception as Error:
            del Error

        # attempt to store the key on a usb
        try:
            with open(os.path.abspath(f"E:/Application_Keys/encryption_keys/key-{str(np.random.randint(0,10000))}.txt"),"wb") as _file:
                # Read the _file
                file_data = _file.write(self.key)
                _file.close()
                
        except Exception as Error:
            del Error
        
        # Disconnect the USB
        self._remove_usb()
        
        
        del self.key,encrypted_data,_file,file_data,path, f
        
            
        
    def genhashes(self):
        # Generate a username for the user.
        User = f"User-{np.random.randint(0,1000000000)}"
        
        
        # Create a pandas DataFrame from a dictionary containing only the hashes.
        Data = pd.DataFrame(
            {
                "Username":self._genKDF_().derive(self.username).decode("IBM819"),
                "Password":self._genKDF_().derive(self.password).decode("IBM819"),
                
            },index=[User]
        )
        
        # Delete the username password from existance.
        del self.username, self.password
        
        # Set path
        try:
            
            path = os.path.abspath("D:/InTheMoneyApplication/Hasher/Users/")
        
        except Exception as Error:
            del Error
            path = os.path.abspath("C:/InTheMoneyApplication/Hasher/Users/")
        
        # Set the absolute path.
        path = os.path.abspath(path+"/"+User+".csv")
        
        # Generate a csv file from the dataframe
        Data.to_csv(path)
        # Encrypt the data
        try:
            
            self._encrypt(path)
        except Exception as statement:
            statement = print("Please connect a usb drive, to continue and set the volume to 5")
            del statement 
            
            os.remove(path)
        os.remove(path)
        
        del Data, path
        
        # Return the generated user
        return User




    
password = "my great password"
username = "greatusername"
key = Hasher(password,username).genhashes()
# if key[1] == key[1]:
#     print(True)
#     print(key[1])
    




# key = hasher(text)._genkey_()

# print(key)
