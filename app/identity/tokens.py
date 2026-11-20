import hashlib
import hmac
import secrets


def hash_token(secret: str, purpose: str, value: str) -> str:
    # El propósito separa dominios: un OTP nunca puede coincidir con el hash de un link o sesión.
    message = f"{purpose}:{value}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def new_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def new_url_token() -> str:
    return secrets.token_urlsafe(32)


def tokens_match(expected_hash: str, candidate_hash: str) -> bool:
    return hmac.compare_digest(expected_hash, candidate_hash)
