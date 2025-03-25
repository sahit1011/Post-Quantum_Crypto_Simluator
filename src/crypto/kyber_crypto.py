"""
Kyber post-quantum encryption module with both simulated and actual lattice-based implementations.
"""
import base64
import json
import os
import hashlib
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .lattice_kyber import LatticeKyber
import numpy as np
import logging

logger = logging.getLogger(__name__)

class KyberCrypto:
    """
    Kyber post-quantum encryption implementation with two modes:
    1. Simulated (default): Uses classical crypto to simulate Kyber's behavior
    2. Lattice: Uses actual lattice-based operations (educational implementation)
    """
    def __init__(self, mode="simulated", security_level="kyber512"):
        """
        Initialize the crypto system.
        
        Args:
            mode: Either "simulated" or "lattice"
            security_level: One of "kyber512", "kyber768", "kyber1024"
        """
        self.mode = mode
        if mode == "lattice":
            self.impl = LatticeKyber(security_level)
            self.impl.generate_keys()  # Generate keys immediately
            self.public_key = None  # Will be generated from lattice keys
            self.private_key = None
        else:
            self.public_key = None
            self.private_key = None
            self.generate_keys()
    
    def generate_keys(self):
        """Generate a new key pair."""
        if self.mode == "lattice":
            return self.impl.generate_keys()
        
        # Simulated mode
        self.private_key = os.urandom(32)
        h = hashlib.sha512()
        h.update(self.private_key)
        self.public_key = h.digest()
    
    def get_public_key_base64(self):
        """Return the public key encoded in base64."""
        if self.mode == "lattice":
            # Convert lattice public key to transportable format
            try:
                pk_bytes = json.dumps({
                    'A': [[a.tolist() for a in row] for row in self.impl.public_key['A']],
                    'b': [b.tolist() for b in self.impl.public_key['b']]
                }).encode()
                return base64.b64encode(pk_bytes).decode('utf-8')
            except Exception as e:
                logger.error(f"Error encoding lattice public key: {str(e)}")
                raise ValueError(f"Failed to encode lattice public key: {str(e)}")
        
        return base64.b64encode(self.public_key).decode('utf-8')
    
    def _generate_shared_secret(self, public_key):
        """Generate a shared secret using the provided public key."""
        if self.mode == "lattice":
            # Convert base64 public key back to lattice format
            pk_dict = json.loads(base64.b64decode(public_key).decode())
            lattice_pk = {
                'A': [[np.array(a, dtype=np.int64) for a in row] for row in pk_dict['A']],
                'b': [np.array(b, dtype=np.int64) for b in pk_dict['b']]
            }
            return self.impl.encapsulate(lattice_pk)
        
        # Simulated mode
        ephemeral_key = os.urandom(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kyber-demo'
        )
        shared_secret = hkdf.derive(ephemeral_key + public_key)
        ciphertext = ephemeral_key + os.urandom(32)
        return ciphertext, shared_secret
    
    def _recover_shared_secret(self, ciphertext):
        """Recover the shared secret from the ciphertext using the private key."""
        if self.mode == "lattice":
            return self.impl.decapsulate(ciphertext)
        
        # Simulated mode
        ephemeral_key = ciphertext[:32]
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'kyber-demo'
        )
        return hkdf.derive(ephemeral_key + self.public_key)
    
    def encrypt(self, message, recipient_public_key_base64=None):
        """Encrypt a message using Kyber encryption."""
        if self.mode == "lattice":
            if recipient_public_key_base64:
                pk_dict = json.loads(base64.b64decode(recipient_public_key_base64).decode())
                lattice_pk = {
                    'A': [[np.array(a, dtype=np.int64) for a in row] for row in pk_dict['A']],
                    'b': [np.array(b, dtype=np.int64) for b in pk_dict['b']]
                }
            else:
                lattice_pk = self.impl.public_key
            
            try:
                ciphertext, shared_secret = self.impl.encapsulate(lattice_pk)
                # Ensure shared secret is exactly 32 bytes for AES
                if len(shared_secret) != 32:
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'kyber-lattice'
                    )
                    shared_secret = hkdf.derive(shared_secret)
            except Exception as e:
                logger.error(f"Error in lattice encryption: {str(e)}")
                raise ValueError(f"Lattice encryption failed: {str(e)}")
        else:
            # Simulated mode
            if recipient_public_key_base64:
                recipient_pk = base64.b64decode(recipient_public_key_base64)
            else:
                recipient_pk = self.public_key
            ciphertext, shared_secret = self._generate_shared_secret(recipient_pk)
        
        try:
            # Use AES-GCM for actual message encryption in both modes
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            
            message_bytes = message.encode('utf-8')
            encrypted_message = encryptor.update(message_bytes) + encryptor.finalize()
            
            result = {
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "tag": base64.b64encode(encryptor.tag).decode('utf-8')
            }
            
            return json.dumps(result)
        except Exception as e:
            logger.error(f"Error in message encryption: {str(e)}")
            return json.dumps({"error": str(e)})
    
    def decrypt(self, encrypted_data):
        """Decrypt a message using Kyber decryption."""
        if not (self.private_key or (self.mode == "lattice" and self.impl.private_key)):
            raise ValueError("Private key not available for decryption")
            
        try:
            data = json.loads(encrypted_data)
            if "error" in data:
                return f"Error in original encryption: {data['error']}"
                
            ciphertext = base64.b64decode(data["ciphertext"])
            encrypted_message = base64.b64decode(data["encrypted_message"])
            nonce = base64.b64decode(data["nonce"])
            tag = base64.b64decode(data["tag"])
            
            shared_secret = self._recover_shared_secret(ciphertext)
            
            # Ensure shared secret is exactly 32 bytes for AES
            if len(shared_secret) != 32:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'kyber-lattice'
                )
                shared_secret = hkdf.derive(shared_secret)
            
            cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
            
            return decrypted_message.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return f"Decryption failed: {str(e)}"
    
    def simulate_quantum_attack(self, encrypted_data, public_key_base64):
        """Simulate a quantum attack on the encryption."""
        start_time = time.time()
        time.sleep(1)  # Simulate computation attempt
        
        mode_str = "lattice-based" if self.mode == "lattice" else "simulated"
        return {
            'success': False,
            'encryption_type': f'Kyber ({mode_str})',
            'time_taken': f"{time.time() - start_time:.2f} seconds",
            'notes': "Kyber encryption is quantum-resistant!\n" +
                    "1. Even quantum computers cannot break lattice-based cryptography\n" +
                    "2. Estimated qubits needed: Millions (beyond current technology)\n" +
                    "3. This demonstrates why Kyber is considered 'post-quantum secure'"
        } 