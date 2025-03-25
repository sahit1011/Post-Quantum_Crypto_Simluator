"""
Custom implementation of Kyber using actual lattice-based cryptography.
This implements the Module-LWE problem and polynomial operations.
"""
import numpy as np
from typing import Tuple, Dict, Optional
import os
import json
import hashlib
import logging

logger = logging.getLogger(__name__)

class PolynomialRing:
    """Ring of polynomials modulo (x^n + 1) with coefficients modulo q"""
    
    def __init__(self, n: int = 256, q: int = 3329):
        self.n = n  # Polynomial degree
        self.q = q  # Coefficient modulus
        
    def add(self, p1: np.ndarray, p2: np.ndarray) -> np.ndarray:
        """Add two polynomials coefficient-wise modulo q"""
        return (p1 + p2) % self.q
    
    def multiply(self, p1: np.ndarray, p2: np.ndarray) -> np.ndarray:
        """Multiply polynomials modulo (x^n + 1) and coefficients modulo q"""
        # Use FFT for efficient multiplication
        result = np.zeros(self.n, dtype=np.int64)
        for i in range(self.n):
            for j in range(self.n):
                if i + j < self.n:
                    result[(i + j) % self.n] = (result[(i + j) % self.n] + p1[i] * p2[j]) % self.q
                else:
                    # Handle reduction modulo (x^n + 1)
                    result[(i + j) % self.n] = (result[(i + j) % self.n] - p1[i] * p2[j]) % self.q
        return result

class ModuleLWE:
    """Implementation of the Module Learning With Errors problem"""
    
    def __init__(self, k: int = 2, n: int = 256, q: int = 3329, eta: int = 2):
        self.k = k      # Module rank
        self.n = n      # Polynomial degree
        self.q = q      # Modulus
        self.eta = eta  # Noise parameter
        self.ring = PolynomialRing(n, q)
    
    def sample_uniform(self) -> np.ndarray:
        """Sample polynomial with uniform coefficients in [0, q-1]"""
        return np.random.randint(0, self.q, size=self.n, dtype=np.int64)
    
    def sample_noise(self) -> np.ndarray:
        """Sample polynomial with coefficients from centered binomial distribution"""
        # Implementation of noise sampling using centered binomial distribution
        a = np.random.randint(0, 2, size=(self.n, self.eta)).sum(axis=1)
        b = np.random.randint(0, 2, size=(self.n, self.eta)).sum(axis=1)
        return (a - b) % self.q

class LatticeKyber:
    """
    Custom implementation of Kyber using actual lattice-based operations.
    This provides an educational view into real post-quantum cryptography.
    """
    
    def __init__(self, security_level: str = "kyber512"):
        """
        Initialize Kyber with specified security level
        
        Args:
            security_level: One of "kyber512" (k=2), "kyber768" (k=3), "kyber1024" (k=4)
        """
        try:
            self.params = {
                "kyber512": {"k": 2, "eta1": 3, "eta2": 2},
                "kyber768": {"k": 3, "eta1": 2, "eta2": 2},
                "kyber1024": {"k": 4, "eta1": 2, "eta2": 2}
            }
            
            if security_level not in self.params:
                raise ValueError(f"Invalid security level. Choose from: {list(self.params.keys())}")
            
            self.k = self.params[security_level]["k"]
            self.eta1 = self.params[security_level]["eta1"]
            self.eta2 = self.params[security_level]["eta2"]
            self.n = 256  # NTT degree
            self.q = 3329  # Modulus
            
            self.mlwe = ModuleLWE(self.k, self.n, self.q, self.eta1)
            self.ring = PolynomialRing(self.n, self.q)
            
            # Initialize keys
            self.public_key = {'A': None, 'b': None}
            self.private_key = {'s': None}
            
            logger.debug(f"Initialized LatticeKyber with security level {security_level}")
            
        except Exception as e:
            logger.error(f"Error initializing LatticeKyber: {str(e)}")
            raise
    
    def generate_keys(self) -> Tuple[Dict, Dict]:
        """
        Generate public and private keys using module-LWE
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Generate random matrix A
            A = [[self.mlwe.sample_uniform() for _ in range(self.k)] for _ in range(self.k)]
            
            # Sample secret vector s with small coefficients
            s = [self.mlwe.sample_noise() for _ in range(self.k)]
            
            # Sample error vector e
            e = [self.mlwe.sample_noise() for _ in range(self.k)]
            
            # Compute b = As + e
            b = [np.zeros(self.n, dtype=np.int64) for _ in range(self.k)]
            for i in range(self.k):
                for j in range(self.k):
                    b[i] = self.ring.add(b[i], self.ring.multiply(A[i][j], s[j]))
                b[i] = self.ring.add(b[i], e[i])
            
            self.public_key = {'A': A, 'b': b}
            self.private_key = {'s': s}
            
            logger.debug("Generated Kyber keys successfully")
            return self.public_key, self.private_key
            
        except Exception as e:
            logger.error(f"Error generating Kyber keys: {str(e)}")
            raise ValueError(f"Failed to generate Kyber keys: {str(e)}")
    
    def encapsulate(self, public_key: Optional[Dict] = None) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the public key
        
        Args:
            public_key: Optional public key to use (uses self.public_key if None)
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        try:
            if public_key is None:
                public_key = self.public_key
            
            if not public_key or not public_key['A'] or not public_key['b']:
                raise ValueError("Invalid public key")
            
            # Sample small random vector r
            r = [self.mlwe.sample_noise() for _ in range(self.k)]
            
            # Sample error vector e1
            e1 = [self.mlwe.sample_noise() for _ in range(self.k)]
            
            # Sample error e2
            e2 = self.mlwe.sample_noise()
            
            # Compute u = A^T r + e1
            u = [np.zeros(self.n, dtype=np.int64) for _ in range(self.k)]
            for i in range(self.k):
                for j in range(self.k):
                    u[i] = self.ring.add(u[i], self.ring.multiply(public_key['A'][j][i], r[j]))
                u[i] = self.ring.add(u[i], e1[i])
            
            # Compute v = b^T r + e2 + ⌊q/2⌋ m
            v = np.zeros(self.n, dtype=np.int64)
            for i in range(self.k):
                v = self.ring.add(v, self.ring.multiply(public_key['b'][i], r[i]))
            v = self.ring.add(v, e2)
            
            # Generate shared secret
            m = hashlib.sha256(np.array(r).tobytes()).digest()
            shared_secret = hashlib.sha256(m).digest()
            
            # Encode ciphertext
            ciphertext = {
                'u': u,
                'v': v.tolist()
            }
            
            # Convert to bytes
            ciphertext_bytes = json.dumps(ciphertext, default=lambda x: x.tolist() if isinstance(x, np.ndarray) else x).encode()
            
            logger.debug("Successfully encapsulated shared secret")
            return ciphertext_bytes, shared_secret
            
        except Exception as e:
            logger.error(f"Error in encapsulation: {str(e)}")
            raise ValueError(f"Failed to encapsulate: {str(e)}")
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret using the private key
        
        Args:
            ciphertext: The ciphertext to decrypt
            
        Returns:
            The shared secret
        """
        try:
            if not self.private_key or not self.private_key['s']:
                raise ValueError("Private key not initialized")
            
            # Decode ciphertext
            try:
                ct_dict = json.loads(ciphertext.decode())
                u = [np.array(x, dtype=np.int64) for x in ct_dict['u']]
                v = np.array(ct_dict['v'], dtype=np.int64)
            except Exception as e:
                raise ValueError(f"Invalid ciphertext format: {str(e)}")
            
            # Compute v - s^T u
            m_rec = v.copy()
            for i in range(self.k):
                m_rec = self.ring.add(m_rec, (-self.ring.multiply(u[i], self.private_key['s'][i])) % self.q)
            
            # Recover the message
            r_rec = [np.zeros(self.n, dtype=np.int64) for _ in range(self.k)]
            for i in range(self.k):
                for j in range(self.n):
                    if abs(m_rec[j]) > self.q // 4:
                        r_rec[i][j] = 1
            
            # Re-derive shared secret
            m = hashlib.sha256(np.array(r_rec).tobytes()).digest()
            shared_secret = hashlib.sha256(m).digest()
            
            logger.debug("Successfully decapsulated shared secret")
            return shared_secret
            
        except Exception as e:
            logger.error(f"Error in decapsulation: {str(e)}")
            raise ValueError(f"Failed to decapsulate: {str(e)}")
    
    def encode_public_key(self) -> bytes:
        """Encode public key as bytes"""
        try:
            if not self.public_key or not self.public_key['A'] or not self.public_key['b']:
                raise ValueError("Public key not initialized")
            return json.dumps(self.public_key, default=lambda x: x.tolist() if isinstance(x, np.ndarray) else x).encode()
        except Exception as e:
            logger.error(f"Error encoding public key: {str(e)}")
            raise
    
    def decode_public_key(self, key_bytes: bytes) -> Dict:
        """Decode public key from bytes"""
        try:
            key_dict = json.loads(key_bytes.decode())
            key_dict['A'] = [[np.array(x, dtype=np.int64) for x in row] for row in key_dict['A']]
            key_dict['b'] = [np.array(x, dtype=np.int64) for x in key_dict['b']]
            return key_dict
        except Exception as e:
            logger.error(f"Error decoding public key: {str(e)}")
            raise ValueError(f"Invalid public key format: {str(e)}") 