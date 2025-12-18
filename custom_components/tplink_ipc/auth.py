"""Authentication utilities for TP-Link IPC devices."""
import hashlib
import base64
from typing import Union, List, Tuple
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key


def org_auth_pwd(password: str) -> str:
    """Original password encoding function."""
    return security_encode(
        password,
        "RDpbLfCPsJZ7fiv",
        "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
    )


def security_encode(a: str, c: str, b: str) -> str:
    """Security encode function."""
    d = ""
    k = 187
    m = 187
    f = len(a)
    g = len(c)
    h = len(b)
    e = f if f > g else g
    
    for l in range(e):
        m = k = 187
        if l >= f:
            m = ord(c[l])
        elif l >= g:
            k = ord(a[l])
        else:
            k = ord(a[l])
            m = ord(c[l])
        d += b[(k ^ m) % h]
    
    return d


def base64_encode_hex(hex_str: str) -> str:
    """Base64 encode hex string (corresponds to U function in JS)."""
    M = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    X = "="
    d = ""
    
    c = 0
    while c + 3 <= len(hex_str):
        b = int(hex_str[c:c+3], 16)
        d += M[b >> 6] + M[b & 63]
        c += 3
    
    if c + 1 == len(hex_str):
        b = int(hex_str[c:c+1], 16)
        d += M[b << 2]
    elif c + 2 == len(hex_str):
        b = int(hex_str[c:c+2], 16)
        d += M[b >> 2] + M[(b & 3) << 4]
    
    while len(d) & 3:
        d += X
    
    return d


def to_pem_public_key(key_base64: str) -> str:
    """Convert base64 public key to PEM format."""
    body = key_base64.replace(" ", "").replace("\n", "").replace("\r", "")
    lines = [body[i:i+64] for i in range(0, len(body), 64)]
    return f"-----BEGIN PUBLIC KEY-----\n{'\n'.join(lines)}\n-----END PUBLIC KEY-----\n"


def rsa_encrypt_base64(plain_text: str, key_base64: str) -> str:
    """RSA encrypt plain text using base64 public key."""
    try:
        # Decode base64 key to DER format
        key_der = base64.b64decode(key_base64)
        # Load public key from DER
        public_key = load_der_public_key(key_der, default_backend())
        # Encrypt
        encrypted = public_key.encrypt(
            plain_text.encode('utf-8'),
            padding.PKCS1v15()
        )
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        raise ValueError(f"RSA encryption failed: {e}")


def encrypt_password_type2(password: str, nonce: str, key: str) -> str:
    """Encrypt password using RSA (encrypt_type "2")."""
    org_auth_password = org_auth_pwd(password)
    plain_text = f"{org_auth_password}:{nonce}"
    
    encrypted = None
    for e in range(50):
        encrypted = rsa_encrypt_base64(plain_text, key)
        
        encrypted_hex = base64.b64decode(encrypted).hex()
        ee = [base64_encode_hex(encrypted_hex), encrypted_hex]
        
        if ee[0] and len(ee[1]) % 64 != 0:
            return ee[0]
    
    return encrypted if encrypted else plain_text


def encrypt_password_type3(password: str, nonce: str) -> str:
    """Encrypt password using MD5 (encrypt_type "3")."""
    return hashlib.md5(f"{password}:{nonce}".encode("utf-8")).hexdigest()


def encrypt_password(
    password: str,
    nonce: str,
    key: str,
    encrypt_type: Union[str, List[str], None]
) -> Tuple[str, str]:
    """
    Encrypt password based on encrypt_type.
    
    Returns:
        tuple: (encrypted_password, encrypt_type_to_use)
    """
    # Determine which encrypt_type to use
    encrypt_type_to_use = "3"  # default
    
    if isinstance(encrypt_type, list):
        # Prefer "2" (RSA) if available, otherwise use first in list
        if "2" in encrypt_type:
            encrypt_type_to_use = "2"
        elif len(encrypt_type) > 0:
            encrypt_type_to_use = str(encrypt_type[0])
    elif encrypt_type:
        encrypt_type_to_use = str(encrypt_type)
    
    # Encrypt based on type
    if encrypt_type_to_use == "2":
        if not key:
            raise ValueError("RSA encryption requires a public key")
        encrypted = encrypt_password_type2(password, nonce, key)
    else:
        # Default to type 3 (MD5)
        encrypted = encrypt_password_type3(password, nonce)
    
    return encrypted, encrypt_type_to_use

