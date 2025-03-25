"""
RSA encryption module with deliberately weak parameters to demonstrate vulnerability.
"""
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long, long_to_bytes
import time
import random
import math

class SimpleRSA:
    """
    Simple RSA implementation for demonstration of small key sizes.
    WARNING: This is for educational purposes only. Do not use in production!
    """
    def __init__(self, key_size=128):
        """Initialize with very small key size for demonstration."""
        self.key_size = key_size
        self.generate_keys()

    def is_prime(self, n, k=5):
        """Simple prime test."""
        if n < 2: return False
        for p in [2,3,5,7,11,13,17,19,23,29]:
            if n % p == 0: return n == p
        s, d = 0, n-1
        while d % 2 == 0:
            s, d = s+1, d//2
        for i in range(k):
            a = random.randrange(2, n-1)
            x = pow(a, d, n)
            if x == 1 or x == n-1: continue
            for r in range(s-1):
                x = (x * x) % n
                if x == 1: return False
                if x == n-1: break
            else: return False
        return True

    def generate_prime(self, bits):
        """Generate a prime number of specified bits."""
        while True:
            n = random.getrandbits(bits)
            if n % 2 == 0: n += 1
            if self.is_prime(n): return n

    def generate_keys(self):
        """Generate public and private keys."""
        # Generate two prime numbers
        bits_per_prime = self.key_size // 2
        self.p = self.generate_prime(bits_per_prime)
        self.q = self.generate_prime(bits_per_prime)
        self.n = self.p * self.q
        
        # Calculate totient
        phi = (self.p - 1) * (self.q - 1)
        
        # Choose public exponent
        self.e = 65537  # Common choice for e
        
        # Calculate private exponent
        self.d = pow(self.e, -1, phi)

    def get_public_key_pem(self):
        """Return public key in a format similar to PEM."""
        return base64.b64encode(f"{self.n},{self.e}".encode()).decode()

    def import_public_key(self, pem):
        """Import public key from our custom format."""
        try:
            decoded = base64.b64decode(pem).decode()
            self.n, self.e = map(int, decoded.split(','))
            return True
        except:
            return False

    def encrypt_simple(self, message):
        """Encrypt a message using simple RSA."""
        message_int = bytes_to_long(message.encode())
        if message_int >= self.n:
            raise ValueError("Message too long for key size")
        encrypted = pow(message_int, self.e, self.n)
        return base64.b64encode(str(encrypted).encode()).decode()

    def decrypt_simple(self, encrypted_message):
        """Decrypt a message using simple RSA."""
        try:
            encrypted_int = int(base64.b64decode(encrypted_message).decode())
            decrypted_int = pow(encrypted_int, self.d, self.n)
            return long_to_bytes(decrypted_int).decode()
        except Exception as e:
            print(f"Simple RSA decryption error: {str(e)}")
            return None

class TinyRSA:
    """A deliberately weak RSA implementation for educational purposes.
    Only supports 16-bit keys to demonstrate vulnerabilities."""
    
    def __init__(self, key_size=16):
        """Initialize TinyRSA with a very small key size."""
        if key_size > 16:
            raise ValueError("TinyRSA only supports key sizes up to 16 bits")
        self.key_size = key_size
        self.e = 65537  # Common public exponent
        
    def _is_prime(self, n):
        """Simple primality test."""
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True
    
    def _generate_prime(self, bits):
        """Generate a prime number with the specified number of bits."""
        while True:
            n = random.getrandbits(bits)
            if n % 2 == 0:  # Ensure odd number
                n += 1
            if self._is_prime(n):
                return n
    
    def generate_keys(self):
        """Generate public and private key pair."""
        # Generate two prime numbers
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        
        # Calculate n and totient
        n = p * q
        totient = (p - 1) * (q - 1)
        
        # Calculate private exponent d
        d = pow(self.e, -1, totient)
        
        return {
            'public': {'n': n, 'e': self.e},
            'private': {'d': d, 'n': n}
        }
    
    def encrypt(self, message, public_key):
        """Encrypt a message using RSA."""
        n = public_key['n']
        e = public_key['e']
        
        # Convert message to number
        m = int.from_bytes(message.encode(), 'big')
        if m >= n:
            raise ValueError("Message too large for key size")
        
        # Encrypt
        c = pow(m, e, n)
        return str(c)
    
    def decrypt(self, ciphertext, private_key):
        """Decrypt a message using RSA."""
        try:
            n = private_key['n']
            d = private_key['d']
            
            # Convert ciphertext to number
            c = int(ciphertext)
            
            # Decrypt
            m = pow(c, d, n)
            
            # Convert number back to bytes and then to string
            decrypted = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            return decrypted.decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return None
    
    def _try_decrypt(self, c, d, n):
        """Try to decrypt with given parameters and validate result."""
        try:
            m = pow(c, d, n)
            decrypted = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            text = decrypted.decode('utf-8')
            # Check if result looks like valid text
            if all(32 <= ord(ch) <= 126 for ch in text):
                return text, True
            # If not valid text, return the numeric value
            return f"(numeric: {m})", False
        except (ValueError, UnicodeDecodeError):
            # Return the raw numeric value when UTF-8 decoding fails
            try:
                return f"(numeric: {m})", False
            except:
                return "(invalid)", False

    def brute_force(self, public_key, ciphertext, progress_callback=None):
        """Attempt to break RSA encryption by trying all possible private keys.
        For educational purposes only - demonstrates why small keys are insecure."""
        n = int(public_key['n'])
        e = int(public_key['e'])
        c = int(ciphertext)
        
        # For 16-bit keys, try all possible values of d
        max_d = min(65536, n)  # 2^16 for 16-bit keys
        
        for d in range(3, max_d, 2):  # Skip even numbers since d must be coprime with totient
            if progress_callback:
                decrypted, valid = self._try_decrypt(c, d, n)
                progress_callback(d, max_d, decrypted, valid)
            
            # Check if this d is valid (e * d ≡ 1 (mod φ(n)))
            # Since we don't know φ(n), we check if decryption works
            decrypted, valid = self._try_decrypt(c, d, n)
            if valid and decrypted:
                # Verify this is actually the correct d by re-encrypting
                try:
                    m = int.from_bytes(decrypted.encode(), 'big')
                    if pow(m, e, n) == c:
                        return {
                            'success': True,
                            'private_key': {'d': d, 'n': n},
                            'decrypted': decrypted,
                            'total_attempts': d
                        }
                except:
                    continue
        
        return {
            'success': False,
            'private_key': None,
            'decrypted': None,
            'total_attempts': max_d
        }

class RSACrypto:
    """RSA encryption implementation."""
    
    def __init__(self, key_size=1024):
        """Initialize RSA with the specified key size."""
        self.key_size = key_size
        
        if key_size <= 16:
            # Use TinyRSA for educational demonstrations
            self.impl = TinyRSA(key_size)
            self.keys = self.impl.generate_keys()
        elif key_size <= 128:
            # Use SimpleRSA for small key demonstrations
            self.impl = SimpleRSA(key_size)
        else:
            # Use real RSA for secure encryption
            self.key = RSA.generate(key_size)
            self.cipher = PKCS1_OAEP.new(self.key)
    
    def get_public_key_pem(self):
        """Return the public key in PEM format."""
        if self.key_size <= 16:
            # For TinyRSA, return n,e as the public key
            return f"{self.keys['public']['n']},{self.keys['public']['e']}"
        elif self.key_size <= 128:
            # For SimpleRSA, use its PEM format
            return self.impl.get_public_key_pem()
        else:
            # For real RSA, return proper PEM format
            return self.key.publickey().export_key().decode()
    
    def encrypt(self, message, recipient_key_pem):
        """Encrypt a message using RSA."""
        try:
            if self.key_size <= 16:
                # For TinyRSA, parse n,e from the public key
                n, e = map(int, recipient_key_pem.split(','))
                return self.impl.encrypt(message, {'n': n, 'e': e})
            elif self.key_size <= 128:
                # For SimpleRSA, use its encryption
                self.impl.import_public_key(recipient_key_pem)
                return self.impl.encrypt_simple(message)
            else:
                # For real RSA, use proper PEM format
                recipient_key = RSA.import_key(recipient_key_pem)
                cipher = PKCS1_OAEP.new(recipient_key)
                encrypted = cipher.encrypt(message.encode())
                return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return None
    
    def decrypt(self, encrypted_message):
        """Decrypt a message using RSA."""
        try:
            if self.key_size <= 16:
                # For TinyRSA, use its decryption
                return self.impl.decrypt(encrypted_message, self.keys['private'])
            elif self.key_size <= 128:
                # For SimpleRSA, use its decryption
                return self.impl.decrypt_simple(encrypted_message)
            else:
                # For real RSA, use proper decryption
                encrypted = base64.b64decode(encrypted_message)
                return self.cipher.decrypt(encrypted).decode()
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return None
    
    def simulate_brute_force(self, public_key, encrypted_message, progress_callback=None):
        """Simulate a brute force attack on RSA encryption."""
        start_time = time.time()
        
        try:
            if self.key_size <= 16:
                # For TinyRSA, use its brute force method
                n, e = map(int, public_key.split(','))
                result = self.impl.brute_force(
                    {'n': n, 'e': e}, 
                    encrypted_message,
                    progress_callback
                )
                
                time_taken = time.time() - start_time
                return {
                    'success': result['success'],
                    'time_taken': time_taken,
                    'decrypted_message': result.get('decrypted'),
                    'notes': 'Successfully broken using brute force.' if result['success'] else 'Failed to break encryption.'
                }
                
            elif self.key_size <= 128:
                # For SimpleRSA, attempt to break it
                self.impl.import_public_key(public_key)
                encrypted_int = int(base64.b64decode(encrypted_message).decode())
                
                # Try values for d up to 2^key_size
                max_d = 1 << self.key_size
                
                for d in range(3, max_d, 2):
                    if progress_callback:
                        try:
                            decrypted_int = pow(encrypted_int, d, self.impl.n)
                            decrypted = long_to_bytes(decrypted_int)
                            text = decrypted.decode('utf-8')
                            progress_callback(d, d, text, all(32 <= ord(ch) <= 126 for ch in text))
                        except:
                            progress_callback(d, d, "(invalid)", False)
                    
                    try:
                        decrypted_int = pow(encrypted_int, d, self.impl.n)
                        decrypted = long_to_bytes(decrypted_int)
                        text = decrypted.decode('utf-8')
                        
                        # Verify this is actually correct by re-encrypting
                        if pow(bytes_to_long(text.encode()), self.impl.e, self.impl.n) == encrypted_int:
                            time_taken = time.time() - start_time
                            return {
                                'success': True,
                                'time_taken': time_taken,
                                'decrypted_message': text,
                                'notes': f'Successfully broken using brute force after trying {d} values.'
                            }
                    except:
                        continue
                
                time_taken = time.time() - start_time
                return {
                    'success': False,
                    'time_taken': time_taken,
                    'decrypted_message': None,
                    'notes': f'Failed to break encryption after {time_taken:.2f} seconds.'
                }
            else:
                # For real RSA, return failure
                time_taken = time.time() - start_time
                return {
                    'success': False,
                    'time_taken': time_taken,
                    'decrypted_message': None,
                    'notes': f'Key size {self.key_size} bits is too large for brute force attack.'
                }
                
        except Exception as e:
            time_taken = time.time() - start_time
            return {
                'success': False,
                'time_taken': time_taken,
                'decrypted_message': None,
                'notes': f'Error during brute force attempt: {str(e)}'
            }