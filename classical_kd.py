# classical_kd.py - Classical Key Distribution replacing BB84 Quantum Key Distribution

import os
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import numpy as np
import time

def classical_shared_key_generation(key_length=64, debug=False):
    """
    Classical replacement for BB84 quantum key distribution.
    Uses cryptographically secure random key generation with CSPRNG.
    
    Args:
        key_length (int): Length of key in bytes (default 64)
        debug (bool): Print debug information
        
    Returns:
        bytes: Cryptographically secure random key
    """
    if debug:
        print(f"🔑 Generating {key_length}-byte classical cryptographic key...")
        print("Using secure random number generation with os.urandom()")
    
    # Generate cryptographically secure random key using OS entropy
    key_bytes = os.urandom(key_length)
    
    # Additional entropy mixing using secrets module
    entropy_supplement = secrets.token_bytes(16)
    
    # Combine with timestamp for additional randomness
    timestamp_bytes = str(time.time_ns()).encode('utf-8')
    
    # Mix all entropy sources using HMAC-SHA256
    combined_entropy = key_bytes + entropy_supplement + timestamp_bytes
    final_key = hmac.new(
        key_bytes[:32],  # Use first 32 bytes as HMAC key
        combined_entropy,
        hashlib.sha256
    ).digest()
    
    # Extend key to desired length if needed
    if key_length > 32:
        extended_key = final_key
        rounds_needed = (key_length - 1) // 32 + 1
        for i in range(1, rounds_needed):
            round_key = hmac.new(
                final_key,
                combined_entropy + i.to_bytes(4, 'big'),
                hashlib.sha256
            ).digest()
            extended_key += round_key
        final_key = extended_key[:key_length]
    elif key_length < 32:
        final_key = final_key[:key_length]
    
    if debug:
        print(f"✅ Generated key: {final_key.hex()[:32]}...")
        print(f"Key length: {len(final_key)} bytes")
        print(f"Entropy quality: {_calculate_entropy_score(final_key):.2f}/8.0")
    
    return final_key

def bb84_shared_key_ibm(key_length=64, debug=False):
    """
    Compatibility function - replaces BB84 quantum key generation with classical equivalent.
    Maintains same interface as original quantum function.
    
    Args:
        key_length (int): Length of key in bytes
        debug (bool): Print debug information
        
    Returns:
        bytes: Cryptographically secure key
    """
    return classical_shared_key_generation(key_length, debug)

def generate_rsa_keypair(key_size=2048):
    """
    Generate RSA key pair for secure key exchange.
    
    Args:
        key_size (int): RSA key size in bits
        
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def secure_key_exchange_simulation(key_length=32, debug=False):
    """
    Simulate secure key exchange using RSA + AES hybrid encryption.
    Replaces quantum key distribution protocol.
    
    Args:
        key_length (int): Desired symmetric key length
        debug (bool): Print debug information
        
    Returns:
        dict: Contains generated key and exchange metadata
    """
    if debug:
        print("🔐 Starting classical key exchange simulation...")
        print("Step 1: Generating RSA key pair...")
    
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keypair()
    
    if debug:
        print("Step 2: Generating symmetric key...")
    
    # Generate symmetric key
    symmetric_key = classical_shared_key_generation(key_length, False)
    
    if debug:
        print("Step 3: Encrypting key with RSA...")
    
    # Encrypt symmetric key with RSA public key
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    if debug:
        print("Step 4: Verifying key exchange...")
    
    # Decrypt to verify (simulating receiver's process)
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Verify keys match
    exchange_successful = decrypted_key == symmetric_key
    
    if debug:
        print(f"✅ Key exchange {'successful' if exchange_successful else 'failed'}")
        print(f"Final key: {symmetric_key.hex()[:32]}...")
    
    return {
        'key': symmetric_key,
        'encrypted_key': encrypted_key,
        'public_key': public_key,
        'exchange_successful': exchange_successful,
        'timestamp': time.time(),
        'key_length': len(symmetric_key)
    }

def _calculate_entropy_score(data):
    """Calculate Shannon entropy score for key quality assessment."""
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate Shannon entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * np.log2(probability)
    
    return entropy

class ClassicalKeyManager:
    """
    Classical key management system replacing quantum key distribution.
    Provides secure key generation, storage, and exchange capabilities.
    """
    
    def __init__(self):
        self.keys = {}  # Store generated keys
        self.key_history = []  # Track key generation history
        
    def generate_voting_key(self, voter_id, key_length=32):
        """
        Generate unique key for voter's ballot encryption.
        
        Args:
            voter_id (str): Unique voter identifier
            key_length (int): Key length in bytes
            
        Returns:
            bytes: Unique voting key
        """
        # Create voter-specific entropy
        voter_entropy = hashlib.sha256(voter_id.encode()).digest()
        timestamp_entropy = str(time.time_ns()).encode()
        
        # Generate base key
        base_key = classical_shared_key_generation(key_length)
        
        # Create voter-specific key by mixing entropies
        voter_key = hmac.new(
            base_key,
            voter_entropy + timestamp_entropy + secrets.token_bytes(16),
            hashlib.sha256
        ).digest()[:key_length]
        
        # Store key metadata
        key_id = hashlib.sha256(voter_id.encode() + voter_key).hexdigest()[:16]
        self.keys[key_id] = {
            'voter_id': voter_id,
            'key': voter_key,
            'generated_at': time.time(),
            'used': False
        }
        
        self.key_history.append({
            'key_id': key_id,
            'voter_id': voter_id,
            'timestamp': time.time(),
            'key_length': key_length
        })
        
        return voter_key
    
    def get_key_stats(self):
        """Get statistics about generated keys."""
        return {
            'total_keys': len(self.keys),
            'keys_used': sum(1 for k in self.keys.values() if k['used']),
            'keys_unused': sum(1 for k in self.keys.values() if not k['used']),
            'generation_history': len(self.key_history)
        }

# Example usage and testing
if __name__ == "__main__":
    print("=== Classical Cryptographic Key Generation System ===")
    print("Replacing BB84 Quantum Key Distribution\n")
    
    # Test basic key generation
    print("1. Testing basic key generation...")
    key = classical_shared_key_generation(32, debug=True)
    print()
    
    # Test BB84 compatibility function
    print("2. Testing BB84 compatibility function...")
    bb84_key = bb84_shared_key_ibm(64, debug=True)
    print()
    
    # Test key exchange simulation
    print("3. Testing secure key exchange simulation...")
    exchange_result = secure_key_exchange_simulation(32, debug=True)
    print(f"Exchange metadata: {exchange_result['exchange_successful']}")
    print()
    
    # Test key manager
    print("4. Testing classical key manager...")
    key_manager = ClassicalKeyManager()
    
    # Generate keys for sample voters
    voter_keys = {}
    for i in range(3):
        voter_id = f"VOTER_{1000 + i}"
        voter_key = key_manager.generate_voting_key(voter_id, 32)
        voter_keys[voter_id] = voter_key
        print(f"Generated key for {voter_id}: {voter_key.hex()[:16]}...")
    
    print(f"\nKey Manager Stats: {key_manager.get_key_stats()}")
    
    print("\n✅ Classical cryptographic system ready!")
    print("🔐 All quantum dependencies successfully replaced with classical equivalents")
    print("🛡️ Maintains security through proven cryptographic methods")