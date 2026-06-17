"""
crypto_utils.py — Primitive crittografiche condivise.

Implementa le operazioni crittografiche del protocollo WP2:
  - RSA-OAEP (cifratura/decifratura voto)
  - RSA-PKCS1v15 / SHA-256 (firma/verifica — approssima RSA-FDH)
  - SHA-256 salted-hash (commitment al voto)
  - Serializzazione canonica dei messaggi
"""

import json
import time
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate


# ── Hashing ───────────────────────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_voter_id(voter_id: str) -> str:
    """H(ID_elettore) — Sezione 11.3"""
    return sha256_hex(voter_id.encode("utf-8"))


def hash_cert(cert_pem: bytes) -> str:
    """H(Cert_e) — usato come chiave in issuedTokens"""
    return sha256_hex(cert_pem)


def hash_token(token_bytes: bytes) -> str:
    """H(token_sessione) — usato come chiave in usedTokens"""
    return sha256_hex(token_bytes)


def hash_ballot(ballot_bytes: bytes) -> str:
    """H(B) — hash della scheda completa serializzata"""
    return sha256_hex(ballot_bytes)


# ── Commitment al voto — Sezione 14.1 ────────────────────────────────────────

def commit_vote(v: int, r_commit: bytes = None) -> tuple[str, bytes]:
    """
    Calcola Commit_voto = SHA-256(v || r_commit).
    Proprietà: hiding (resistenza preimmagine) + binding (resistenza collisioni).

    Args:
        v:        bit di voto {0, 1}
        r_commit: fattore di randomizzazione 256 bit (generato se None)

    Returns:
        (commit_hex, r_commit_bytes)
    """
    if r_commit is None:
        r_commit = secrets.token_bytes(32)
    data    = bytes([v]) + r_commit
    commit  = sha256_hex(data)
    return commit, r_commit


def verify_commit(v: int, r_commit: bytes, commit_hex: str) -> bool:
    """Verifica che SHA-256(v || r_commit) == commit_hex."""
    expected, _ = commit_vote(v, r_commit)
    return expected == commit_hex


# ── RSA-OAEP — Sezione 14.2.1 ────────────────────────────────────────────────

def encrypt_vote(v: int, pk_as: rsa.RSAPublicKey) -> tuple[bytes, bytes]:
    """
    Cifratura RSA-OAEP del voto: C_voto = Enc_pkAS(v || r_voto).
    Garantisce CPA-security e non-malleabilità.

    Returns:
        (c_voto_bytes, r_voto_bytes)
    """
    r_voto    = secrets.token_bytes(16)
    plaintext = bytes([v]) + r_voto
    c_voto    = pk_as.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return c_voto, r_voto


def decrypt_vote(c_voto: bytes, sk_as: rsa.RSAPrivateKey) -> int:
    """
    Decifratura RSA-OAEP: v = Dec_skAS(C_voto).
    Restituisce il bit di voto {0, 1}.
    """
    plaintext = sk_as.decrypt(
        c_voto,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    v = plaintext[0]
    if v not in (0, 1):
        raise ValueError(f"Voto decifrato non valido: {v}")
    return v


# ── Firma RSA (approssima FDH con PKCS1v15+SHA256) ───────────────────────────

def sign(sk: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Firma digitale: Sign_sk(data).
    Usa PKCS1v15 con SHA-256 (approssimazione didattica di RSA-FDH).
    """
    return sk.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_sig(pk: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Verifica firma: Vrfy_pk(data, sig) = 1."""
    try:
        pk.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


# ── Serializzazione canonica ──────────────────────────────────────────────────

def canonical_bytes(obj: dict) -> bytes:
    """Serializzazione deterministica di un dict in bytes (per hashing e firma)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ── Chiavi RSA — helpers I/O ─────────────────────────────────────────────────

def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key_from_cert(cert_pem: bytes) -> rsa.RSAPublicKey:
    return load_pem_x509_certificate(cert_pem).public_key()


def pubkey_to_der_b64(pk: rsa.RSAPublicKey) -> str:
    der = pk.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64e(der)


def pubkey_from_der_b64(s: str) -> rsa.RSAPublicKey:
    der = b64d(s)
    return serialization.load_der_public_key(der)


# ── Token di sessione — Sezione 13.4 ─────────────────────────────────────────

def build_token(pk_e: rsa.RSAPublicKey, nonce: bytes, ts: float,
                ts_exp: float, sk_ar: rsa.RSAPrivateKey) -> dict:
    """
    Costruisce il token: Token = Sign_skAR(pk_e || nonce || ts || ts_exp).

    Struttura JSON:
      { "payload": {...}, "sig": "<base64>" }
    """
    payload = {
        "pk_e_der_b64": pubkey_to_der_b64(pk_e),
        "nonce":        nonce.hex(),
        "ts":           ts,
        "ts_exp":       ts_exp,
    }
    sig = sign(sk_ar, sha256_bytes(canonical_bytes(payload)))
    return {"payload": payload, "sig": b64e(sig)}


def verify_token(token: dict, pk_ar: rsa.RSAPublicKey) -> bool:
    """Verifica la firma di AR sul token."""
    try:
        sig = b64d(token["sig"])
        return verify_sig(pk_ar, sha256_bytes(canonical_bytes(token["payload"])), sig)
    except Exception:
        return False


def extract_pk_e_from_token(token: dict) -> rsa.RSAPublicKey:
    """Estrae pk_e direttamente dal payload del token (già autenticato da AR)."""
    return pubkey_from_der_b64(token["payload"]["pk_e_der_b64"])


def token_to_bytes(token: dict) -> bytes:
    """Serializza il token per hashing (H(token_sessione))."""
    return canonical_bytes(token)


# ── Scheda di voto — Sezione 14 ──────────────────────────────────────────────

def build_ballot(c_voto: bytes, commit_voto: str, token: dict,
                 ts_voto: float, nonce_voto: bytes,
                 sk_e: rsa.RSAPrivateKey) -> tuple[dict, bytes]:
    """
    Costruisce la scheda B e la firma con sk_e.

    σ_scheda = Sign_ske(H(C_voto || Commit_voto || token || ts_voto || nonce_voto))
    B = (C_voto, Commit_voto, token, ts_voto, nonce_voto, σ_scheda)

    Returns:
        (ballot_dict, ballot_bytes_for_hashing)
    """
    # Payload da firmare (esclude σ_scheda)
    payload_fields = {
        "c_voto_b64":   b64e(c_voto),
        "commit_voto":  commit_voto,
        "token":        token,
        "ts_voto":      ts_voto,
        "nonce_voto":   nonce_voto.hex(),
    }
    h_payload = sha256_bytes(canonical_bytes(payload_fields))
    sigma     = sign(sk_e, h_payload)

    ballot = {**payload_fields, "sigma_scheda_b64": b64e(sigma)}
    ballot_bytes = canonical_bytes(ballot)
    return ballot, ballot_bytes


def verify_ballot_signature(ballot: dict, pk_e: rsa.RSAPublicKey) -> bool:
    """Verifica σ_scheda sulla scheda ricevuta."""
    try:
        sigma = b64d(ballot["sigma_scheda_b64"])
        payload_fields = {k: v for k, v in ballot.items() if k != "sigma_scheda_b64"}
        h = sha256_bytes(canonical_bytes(payload_fields))
        return verify_sig(pk_e, h, sigma)
    except Exception:
        return False


# ── Receipt — Sezione 14.2.2 ─────────────────────────────────────────────────

def build_receipt(ballot_hash: str, seq_num: int, ts_reg: float,
                  sk_ar: rsa.RSAPrivateKey) -> dict:
    """
    Receipt = Sign_skAR(H(B) || seq_num || ts_registrazione)
    """
    payload = {"ballot_hash": ballot_hash, "seq_num": seq_num, "ts_reg": ts_reg}
    sig     = sign(sk_ar, sha256_bytes(canonical_bytes(payload)))
    return {"payload": payload, "sig": b64e(sig)}


def verify_receipt(receipt: dict, pk_ar: rsa.RSAPublicKey) -> bool:
    """Verifica la firma di AR sulla ricevuta."""
    try:
        sig = b64d(receipt["sig"])
        return verify_sig(pk_ar, sha256_bytes(canonical_bytes(receipt["payload"])), sig)
    except Exception:
        return False


# ── Trasmissione cifrata delle share (CRITICA-2) ──────────────────────────────

def encrypt_share(share: int, guardian_id: int,
                  pk_as_recv: rsa.RSAPublicKey,
                  nonce_size: int = 16) -> dict:
    """
    Cifra una share Shamir per la trasmissione ad AS (encrypt-then-sign).
    La share è grande ~2048 bit: si usa cifratura ibrida RSA-OAEP + AES-GCM.

    Plaintext: JSON(share, guardian_id, nonce, ts)
    Restituisce un dict con enc_key_b64, gcm_nonce_b64, ciphertext_b64.
    """
    nonce     = secrets.token_bytes(nonce_size)
    ts        = time.time()
    plaintext = json.dumps({
        "share":       str(share),
        "guardian_id": guardian_id,
        "nonce":       nonce.hex(),
        "ts":          ts,
    }, sort_keys=True).encode("utf-8")

    aes_key   = secrets.token_bytes(32)
    gcm_nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(gcm_nonce, plaintext, None)

    enc_key = pk_as_recv.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    return {
        "enc_key_b64":    b64e(enc_key),
        "gcm_nonce_b64":  b64e(gcm_nonce),
        "ciphertext_b64": b64e(ciphertext),
    }


def decrypt_share(packet: dict, sk_as_recv: rsa.RSAPrivateKey) -> tuple:
    """
    Decifra un pacchetto share ricevuto da un garante.
    Restituisce (share: int, guardian_id: int, nonce: bytes, ts: float).
    """
    aes_key = sk_as_recv.decrypt(
        b64d(packet["enc_key_b64"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    gcm_nonce  = b64d(packet["gcm_nonce_b64"])
    ciphertext = b64d(packet["ciphertext_b64"])
    plaintext  = AESGCM(aes_key).decrypt(gcm_nonce, ciphertext, None)
    data       = json.loads(plaintext.decode("utf-8"))
    return (
        int(data["share"]),
        int(data["guardian_id"]),
        bytes.fromhex(data["nonce"]),
        float(data["ts"]),
    )


def sign_share_packet(packet: dict, sk_guardian: rsa.RSAPrivateKey) -> bytes:
    """Firma il pacchetto share cifrato con la chiave privata del garante."""
    return sign(sk_guardian, sha256_bytes(canonical_bytes(packet)))


def verify_share_packet(packet: dict, signature: bytes,
                        pk_guardian: rsa.RSAPublicKey) -> bool:
    """Verifica la firma sul pacchetto share cifrato."""
    return verify_sig(pk_guardian, sha256_bytes(canonical_bytes(packet)), signature)
