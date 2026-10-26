
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = Path(__file__).resolve().parent
KEY_DIR = BASE_DIR / "data" / "keys"

PRIVATE_KEY_PATH = KEY_DIR / "ambulance_signing_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "ambulance_signing_public.pem"


def generate_signing_keys():
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Never overwrite an existing signing key.
    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        raise FileExistsError(
            "A signing key already exists. "
            "Check data/keys before generating another pair."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save the private key first; restrict file permissions where supported.
    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    try:
        PRIVATE_KEY_PATH.chmod(0o600)
    except OSError:
        pass

    print("Ambulance signing key pair generated.")
    print(f"Private key: {PRIVATE_KEY_PATH}")
    print(f"Public key:  {PUBLIC_KEY_PATH}")
    print("Keep the private signing key secret.")


if __name__ == "__main__":
    generate_signing_keys()
