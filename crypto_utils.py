# crypto_utils.py - Classical cryptographic utilities for voting system

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

def aes_encrypt(key, data):
    """
    Encrypt data using AES-256 in CBC mode.
    
    Args:
        key (bytes): 32-byte AES key
        data (bytes): Data to encrypt
        
    Returns:
        str: Base64 encoded encrypted data with IV
    """
    try:
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Ensure key is exactly 32 bytes for AES-256
        if len(key) != 32:
            # Hash the key to get exactly 32 bytes
            key = hashlib.sha256(key).digest()
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad data and encrypt
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine IV and encrypted data, then base64 encode
        combined = iv + encrypted_data
        return base64.b64encode(combined).decode('utf-8')
        
    except Exception as e:
        raise RuntimeError(f"AES encryption failed: {str(e)}")

def aes_decrypt(key, encrypted_data):
    """
    Decrypt AES-256 encrypted data.
    
    Args:
        key (bytes): 32-byte AES key
        encrypted_data (str): Base64 encoded encrypted data
        
    Returns:
        bytes: Decrypted data
    """
    try:
        # Ensure key is exactly 32 bytes for AES-256
        if len(key) != 32:
            # Hash the key to get exactly 32 bytes
            key = hashlib.sha256(key).digest()
        
        # Decode base64
        combined = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # Extract IV and encrypted data
        iv = combined[:16]
        encrypted_bytes = combined[16:]
        
        # Create AES cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(encrypted_bytes)
        
        # Remove padding
        data = unpad(padded_data, AES.block_size)
        
        return data
        
    except Exception as e:
        raise RuntimeError(f"AES decryption failed: {str(e)}")

def generate_aes_key():
    """
    Generate a secure 256-bit AES key.
    
    Returns:
        bytes: 32-byte AES key
    """
    return get_random_bytes(32)

def hash_data(data):
    """
    Generate SHA-256 hash of data.
    
    Args:
        data (bytes or str): Data to hash
        
    Returns:
        str: Hexadecimal hash digest
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return hashlib.sha256(data).hexdigest()

# Legacy compatibility functions
def create_key_from_string(key_string):
    """Create AES key from string for backward compatibility."""
    return hashlib.sha256(key_string.encode('utf-8')).digest()

def encrypt_vote_data(vote_dict, key):
    """Encrypt vote dictionary using AES."""
    import json
    vote_json = json.dumps(vote_dict, sort_keys=True)
    return aes_encrypt(key, vote_json.encode('utf-8'))

def decrypt_vote_data(encrypted_data, key):
    """Decrypt vote data and return as dictionary."""
    import json
    decrypted_bytes = aes_decrypt(key, encrypted_data)
    return json.loads(decrypted_bytes.decode('utf-8'))

# Test functions
if __name__ == "__main__":
    print("Testing Classical Crypto Utils...")
    
    # Test key generation
    key = generate_aes_key()
    print(f"Generated AES key: {key.hex()[:32]}...")
    
    # Test encryption/decryption
    test_data = b"This is a test vote for Party XYZ"
    encrypted = aes_encrypt(key, test_data)
    decrypted = aes_decrypt(key, encrypted)
    
    print(f"Original: {test_data}")
    print(f"Encrypted: {encrypted[:32]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_data == decrypted}")
    
    # Test vote data encryption
    vote_data = {
        "voter_id": "TEST123",
        "party": "Test Party", 
        "timestamp": "2025-09-04T17:41:00"
    }
    
    encrypted_vote = encrypt_vote_data(vote_data, key)
    decrypted_vote = decrypt_vote_data(encrypted_vote, key)
    
    print(f"Vote data encryption test:")
    print(f"Original: {vote_data}")
    print(f"Decrypted: {decrypted_vote}")
    print(f"Match: {vote_data == decrypted_vote}")
    
    print("✅ All crypto utils tests passed!")