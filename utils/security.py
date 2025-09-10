import hashlib
import os
import binascii

def hash_password(password):
    if password is None:
        return None
        
    salt = os.urandom(16)
    
    hashed = hashlib.sha256(salt + password.encode()).hexdigest()
    
    return binascii.hexlify(salt).decode() + hashed

def verify_password(password, stored_hash):

    if stored_hash is None and password is None:
        return True
        
    if stored_hash is None or password is None:
        return False
    
    salt_hex = stored_hash[:32]
    salt = binascii.unhexlify(salt_hex)
    
    test_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    
    return stored_hash[32:] == test_hash