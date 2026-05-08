import random
import time
import json
import smtplib
from email.mime.text import MIMEText

# --- MATH HELPERS ---
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(a, m):
    a = a % m
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    return x % m

def power(base, exp, mod):
    res = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            res = (res * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return res

def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = power(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

# --- RSA IMPLEMENTATION ---
class CustomRSA:
    @staticmethod
    def generate_keys(bits=256):
        p = generate_prime(bits)
        q = generate_prime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while gcd(e, phi) != 1:
            e += 2
        d = mod_inverse(e, phi)
        return (e, n), (d, n)

    @staticmethod
    def encrypt(message: str, pub_key: tuple) -> list:
        e, n = pub_key
        # Block-Asymmetric Chunking
        chunk_size = max(1, (n.bit_length() // 8) - 1)
        encoded = message.encode('utf-8')
        cipher_blocks = []
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i+chunk_size]
            m = int.from_bytes(chunk, byteorder='big')
            c = power(m, e, n)
            cipher_blocks.append(c)
        return cipher_blocks

    @staticmethod
    def decrypt(cipher_blocks: list, priv_key: tuple) -> str:
        d, n = priv_key
        decrypted_bytes = bytearray()
        for c in cipher_blocks:
            m = power(c, d, n)
            chunk = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
            decrypted_bytes.extend(chunk)
        return decrypted_bytes.decode('utf-8', errors='ignore')

# --- ECC IMPLEMENTATION ---
ECC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ECC_A = 0
ECC_B = 7
ECC_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)
ECC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class CustomECC:
    @staticmethod
    def point_add(p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        x1, y1 = p1
        x2, y2 = p2
        
        if x1 == x2 and y1 != y2:
            return None
            
        if x1 == x2:
            m = (3 * x1 * x1 + ECC_A) * mod_inverse(2 * y1, ECC_P)
        else:
            m = (y2 - y1) * mod_inverse(x2 - x1, ECC_P)
            
        m = m % ECC_P
        x3 = (m * m - x1 - x2) % ECC_P
        y3 = (m * (x1 - x3) - y1) % ECC_P
        return (x3, y3)

    @staticmethod
    def scalar_mult(k, point):
        res = None
        addend = point
        k = k % ECC_N
        while k > 0:
            if k & 1:
                res = CustomECC.point_add(res, addend)
            addend = CustomECC.point_add(addend, addend)
            k >>= 1
        return res

    @staticmethod
    def generate_keys():
        priv = random.randint(1, ECC_N - 1)
        pub = CustomECC.scalar_mult(priv, ECC_G)
        return pub, priv

    @staticmethod
    def encrypt(message: str, pub_key: tuple) -> list:
        encoded = message.encode('utf-8')
        chunk_size = 30 # Fits within field size safely
        cipher_blocks = []
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i+chunk_size]
            m = int.from_bytes(chunk, byteorder='big')
            k = random.randint(1, ECC_N - 1)
            c1 = CustomECC.scalar_mult(k, ECC_G)
            shared_secret = CustomECC.scalar_mult(k, pub_key)
            c2 = (m + shared_secret[0]) % ECC_P
            cipher_blocks.append((c1, c2))
        return cipher_blocks

    @staticmethod
    def decrypt(cipher_blocks: list, priv_key: int) -> str:
        decrypted_bytes = bytearray()
        for c1, c2 in cipher_blocks:
            shared_secret = CustomECC.scalar_mult(priv_key, c1)
            m = (c2 - shared_secret[0]) % ECC_P
            chunk = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
            decrypted_bytes.extend(chunk)
        return decrypted_bytes.decode('utf-8', errors='ignore')

# --- HASHING & HMAC IMPLEMENTATION ---
class CustomHash:
    @staticmethod
    def hash(message: str) -> str:
        # Simple FNV-1a like hash
        h = 0x811c9dc5
        for char in message:
            h = h ^ ord(char)
            h = (h * 0x01000193) & 0xFFFFFFFF
        return hex(h)[2:].zfill(8)

class CustomHMAC:
    @staticmethod
    def compute(key: str, message: str) -> str:
        block_size = 64
        if len(key) > block_size:
            key = CustomHash.hash(key)
        key = key.ljust(block_size, '\x00')
        
        o_key_pad = "".join(chr(ord(k) ^ 0x5c) for k in key)
        i_key_pad = "".join(chr(ord(k) ^ 0x36) for k in key)
        
        inner_hash = CustomHash.hash(i_key_pad + message)
        return CustomHash.hash(o_key_pad + inner_hash)

# --- PASSWORD SECURITY ---
class PasswordAuth:
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple:
        if not salt:
            salt = hex(random.getrandbits(64))[2:]
        return CustomHash.hash(password + salt), salt
    
    @staticmethod
    def verify(password: str, hashed: str, salt: str) -> bool:
        return CustomHash.hash(password + salt) == hashed

# --- 2FA IMPLEMENTATION ---
class TwoFactorAuth:
    OTP_STORE = {} # In-memory store for OTPs: {email: (otp, expiry)}

    @staticmethod
    def generate_otp(email: str):
        otp = str(random.randint(100000, 999999))
        TwoFactorAuth.OTP_STORE[email] = (otp, time.time() + 300) # 5 min expiry
        
        # --- REAL EMAIL SENDING LOGIC ---
        sender_email = "YOUR_EMAIL@GMAIL.COM" # Enter your sender email
        sender_password = "xxxx xxxx xxxx xxxx" # Enter your Google App Password
        
        msg = MIMEText(f"Your 2FA Verification Code for BRAC Whistleblowing System is: {otp}")
        msg['Subject'] = "BRAC Whistleblowing 2FA Code"
        msg['From'] = f"BRAC Security <{sender_email}>"
        msg['To'] = email

        print(f"\n[SYSTEM] Attempting to send real 2FA email to {email}...")
        try:
            # Connect to Gmail SMTP
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            print(f"[SYSTEM] OTP Sent successfully to {email}\n")
        except Exception as e:
            print(f"[SYSTEM] SMTP Error: {e}")
            print(f"[SYSTEM] FALLBACK OTP (Check Console): {otp}\n")
        
        return otp

    @staticmethod
    def verify_otp(email: str, otp: str):
        if email not in TwoFactorAuth.OTP_STORE:
            return False
        stored_otp, expiry = TwoFactorAuth.OTP_STORE[email]
        if time.time() > expiry:
            del TwoFactorAuth.OTP_STORE[email]
            return False
        return stored_otp == otp

# --- SECURE SESSION MANAGEMENT ---
class SessionManager:
    SECRET = "system_super_secret_session_key_123"
    
    @staticmethod
    def create_token(user_id: int, role: str) -> str:
        header = '{"alg": "CUSTOM-HMAC", "typ": "JWT"}'
        expiry = int(time.time()) + 3600 # 1 hour
        payload = json.dumps({"user_id": user_id, "role": role, "exp": expiry})
        
        header_enc = header.encode().hex()
        payload_enc = payload.encode().hex()
        
        signature = CustomHMAC.compute(SessionManager.SECRET, f"{header_enc}.{payload_enc}")
        return f"{header_enc}.{payload_enc}.{signature}"

    @staticmethod
    def verify_token(token: str) -> dict:
        parts = token.split('.')
        if len(parts) != 3:
            raise Exception("Invalid token format")
            
        header_enc, payload_enc, signature = parts
        expected_sig = CustomHMAC.compute(SessionManager.SECRET, f"{header_enc}.{payload_enc}")
        
        if signature != expected_sig:
            raise Exception("Invalid token signature")
            
        payload = bytes.fromhex(payload_enc).decode()
        data = json.loads(payload)
        
        if int(time.time()) > data['exp']:
            raise Exception("Token expired")
            
        return data
