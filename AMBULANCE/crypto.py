# ============================================================
# SMART AMBULANCE - ENCRYPTION AND KEY MANAGEMENT
# AES-256-GCM + RSA-OAEP-SHA256
# ============================================================

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ============================================================
# PATHS
# ============================================================

KEYS_DIR = os.path.join("data", "keys")

HOSPITAL_PUBLIC_KEY_PATH = os.path.join(
    KEYS_DIR, "hospital_public.pem"
)

HOSPITAL_PRIVATE_KEY_PATH = os.path.join(
    KEYS_DIR, "hospital_private.pem"
)


# ============================================================
# GENERATE A FRESH AES-256 KEY FOR EACH EVENT
# ============================================================

def generate_key():
    return AESGCM.generate_key(bit_length=256)


# ============================================================
# AES-256-GCM ENCRYPTION
# ============================================================

def encrypt_data(data, key):
    if isinstance(data, str):
        data = data.encode("utf-8")

    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    return nonce, ciphertext


# ============================================================
# AES-256-GCM DECRYPTION
# ============================================================

def decrypt_data(nonce, ciphertext, key):
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


# ============================================================
# SHA-256 INTEGRITY HASH
# ============================================================

def calculate_sha256(nonce, ciphertext):
    digest = hashlib.sha256(
        nonce + ciphertext
    ).hexdigest()

    return digest


# ============================================================
# GENERATE HOSPITAL RSA KEY PAIR
# Run once using generate_hospital_keys.py.
# Never regenerate this pair for each patient event.
# ============================================================

def generate_hospital_key_pair():
    os.makedirs(KEYS_DIR, exist_ok=True)

    if (
        os.path.exists(HOSPITAL_PUBLIC_KEY_PATH)
        or os.path.exists(HOSPITAL_PRIVATE_KEY_PATH)
    ):
        raise FileExistsError(
            "A hospital key file already exists. "
            "Refusing to overwrite existing keys."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_created = False

    try:
        # Exclusive creation prevents overwriting an existing file.
        with open(HOSPITAL_PRIVATE_KEY_PATH, "xb") as file:
            file.write(private_pem)
        private_created = True

        with open(HOSPITAL_PUBLIC_KEY_PATH, "xb") as file:
            file.write(public_pem)

    except Exception:
        # Avoid leaving a partial key pair after a failed creation.
        if private_created and not os.path.exists(HOSPITAL_PUBLIC_KEY_PATH):
            try:
                os.remove(HOSPITAL_PRIVATE_KEY_PATH)
            except OSError:
                pass
        raise

    # Restrict private-key permissions where supported.
    try:
        os.chmod(HOSPITAL_PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass

    print("Hospital RSA key pair generated.")
    print(f"Public key:  {HOSPITAL_PUBLIC_KEY_PATH}")
    print(f"Private key: {HOSPITAL_PRIVATE_KEY_PATH}")
    print("Keep the private key secure and separate from the ledger.")


# ============================================================
# LOAD HOSPITAL PUBLIC KEY
# ============================================================

def load_hospital_public_key():
    """Load the hospital public RSA key.
    Checks the HOSPITAL_PUBLIC_KEY environment variable first; if set, expects a PEM
    string (base64‑encoded or raw) and loads it directly. Falls back to the key file.
    """
    pem = os.getenv("HOSPITAL_PUBLIC_KEY")
    if pem:
        try:
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        except Exception as e:
            raise ValueError("Failed to load HOSPITAL_PUBLIC_KEY from env var: " + str(e))
    else:
        with open(HOSPITAL_PUBLIC_KEY_PATH, "rb") as file:
            public_key = serialization.load_pem_public_key(
                file.read()
            )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Hospital public key is not an RSA key.")
    return public_key

def load_hospital_public_key_from_env():
    """Load hospital public key from HOSPITAL_PUBLIC_KEY env var if set, else fallback to file.
    Returns RSA public key object."""
    pem = os.getenv("HOSPITAL_PUBLIC_KEY")
    if pem:
        try:
            return serialization.load_pem_public_key(pem.encode("utf-8"))
        except Exception as e:
            raise ValueError("Failed to load HOSPITAL_PUBLIC_KEY from env var: " + str(e))
    # fallback to file
    with open(HOSPITAL_PUBLIC_KEY_PATH, "rb") as file:
        return serialization.load_pem_public_key(file.read())


# ============================================================
# WRAP THE FRESH AES KEY USING RSA-OAEP-SHA256
# ============================================================

def wrap_aes_key(aes_key, public_key=None):
    if public_key is None:
        public_key = load_hospital_public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Hospital public key is not an RSA key.")

    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )



# ============================================================
# UNWRAP AES KEY USING THE HOSPITAL PRIVATE KEY
# Intended for the hospital-side backend.
# ============================================================

def unwrap_aes_key(wrapped_key, private_key_path=None):
    if private_key_path is None:
        private_key_path = HOSPITAL_PRIVATE_KEY_PATH

    with open(private_key_path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Hospital private key is not an RSA key.")

    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ============================================================
# AMBULANCE DIGITAL SIGNATURE
# ============================================================

AMBULANCE_SIGNING_PRIVATE_KEY_PATH = os.path.join(
    KEYS_DIR, "ambulance_signing_private.pem"
)


def sign_event(data: bytes) -> bytes:
    """Sign event bytes using the ambulance's private signing key."""

    private_key_pem = os.getenv("AMBULANCE_SIGNING_PRIVATE_KEY")

    if private_key_pem:
        private_key_data = private_key_pem.replace("\\n", "\n").encode()
    else:
        with open(AMBULANCE_SIGNING_PRIVATE_KEY_PATH, "rb") as file:
            private_key_data = file.read()

    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Ambulance signing key is not an RSA private key.")

    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )