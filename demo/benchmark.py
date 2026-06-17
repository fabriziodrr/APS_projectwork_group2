"""
benchmark.py — Misurazione dei tempi delle operazioni crittografiche del sistema APS.

Esegue ogni operazione N volte e riporta: media, minimo, massimo e deviazione standard
in millisecondi. Produce un riepilogo testuale e un file JSON (benchmark_results.json)
con i dati grezzi, utilizzabile per la compilazione della tabella nel WP4.

Uso:
    python benchmark.py           — esecuzione standard
    python benchmark.py --fast    — riduce le iterazioni per un'anteprima rapida
"""

import sys
import time
import json
import secrets
import statistics
import hashlib
import base64
import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

# ── Parametri ─────────────────────────────────────────────────────────────────

FAST_MODE = "--fast" in sys.argv
N_FAST    = 5  if FAST_MODE else 50
N_MED     = 3  if FAST_MODE else 20
N_SLOW    = 1  if FAST_MODE else 5
RSA_BITS  = 2048


# ── Utilità ───────────────────────────────────────────────────────────────────

def ms(t: float) -> float:
    return t * 1000.0


def run_bench(label: str, fn, n: int) -> dict:
    """Esegue fn() n volte, raccoglie i tempi e restituisce le statistiche in ms."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    vals = [ms(t) for t in times]
    result = {
        "label": label,
        "n":     n,
        "mean":  round(statistics.mean(vals),              3),
        "min":   round(min(vals),                          3),
        "max":   round(max(vals),                          3),
        "stdev": round(statistics.stdev(vals) if n > 1 else 0.0, 3),
    }
    print(f"  {label:<54} {result['mean']:>9.3f} ms  "
          f"(min={result['min']:.3f}  max={result['max']:.3f}  n={n})")
    return result


# ── Generazione chiavi di supporto ────────────────────────────────────────────

print("\n[benchmark] Generazione chiavi RSA di supporto per i test...")
_ca_key      = rsa.generate_private_key(65537, RSA_BITS, default_backend())
_ar_key      = rsa.generate_private_key(65537, RSA_BITS, default_backend())
_as_key      = rsa.generate_private_key(65537, RSA_BITS, default_backend())
_voter_key   = rsa.generate_private_key(65537, RSA_BITS, default_backend())
_guardian_key = rsa.generate_private_key(65537, RSA_BITS, default_backend())

_ca_pub      = _ca_key.public_key()
_ar_pub      = _ar_key.public_key()
_as_pub      = _as_key.public_key()
_voter_pub   = _voter_key.public_key()

_test_data   = secrets.token_bytes(64)
_nonce       = secrets.token_bytes(16)
_aes_key     = secrets.token_bytes(32)
_gcm_nonce   = secrets.token_bytes(12)
_r_commit    = secrets.token_bytes(32)
_vote_bit    = 1
print("[benchmark] Setup completato.\n")


# ── Definizione delle operazioni da misurare ──────────────────────────────────

# 1. SHA-256
def _sha256_64():
    hashlib.sha256(_test_data).digest()

def _sha256_100k():
    hashlib.sha256(secrets.token_bytes(100 * 1024)).digest()

def _commit_vote():
    hashlib.sha256(bytes([_vote_bit]) + _r_commit).hexdigest()

# 2. Firma / verifica RSA-PKCS1v15 + SHA-256
def _sign():
    _ar_key.sign(_test_data, padding.PKCS1v15(), hashes.SHA256())

_sig_cached = _ar_key.sign(_test_data, padding.PKCS1v15(), hashes.SHA256())
def _verify():
    try:
        _ar_pub.verify(_sig_cached, _test_data, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        pass

# 3. RSA-OAEP cifratura/decifratura
def _oaep_encrypt():
    msg = bytes([_vote_bit]) + secrets.token_bytes(16)
    _as_pub.encrypt(msg, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

_c_voto = _as_pub.encrypt(bytes([_vote_bit]) + secrets.token_bytes(16),
                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(), label=None))
def _oaep_decrypt():
    _as_key.decrypt(_c_voto, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

# 4. AES-256-GCM
def _aes_enc():
    AESGCM(_aes_key).encrypt(_gcm_nonce, _test_data, None)

_gcm_ct = AESGCM(_aes_key).encrypt(_gcm_nonce, _test_data, None)
def _aes_dec():
    AESGCM(_aes_key).decrypt(_gcm_nonce, _gcm_ct, None)

# 5. Cifratura ibrida share (RSA-OAEP + AES-GCM)
def _encrypt_share():
    plaintext = json.dumps({"share": str(12345), "guardian_id": 1,
                             "nonce": secrets.token_bytes(16).hex(),
                             "ts": time.time()}, sort_keys=True).encode()
    enc_key = _as_pub.encrypt(_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    ct = AESGCM(_aes_key).encrypt(_gcm_nonce, plaintext, None)
    return {"enc_key_b64":    base64.b64encode(enc_key).decode(),
            "gcm_nonce_b64":  base64.b64encode(_gcm_nonce).decode(),
            "ciphertext_b64": base64.b64encode(ct).decode()}

_share_pkt = _encrypt_share()
def _decrypt_share():
    k = _as_key.decrypt(base64.b64decode(_share_pkt["enc_key_b64"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    AESGCM(k).decrypt(base64.b64decode(_share_pkt["gcm_nonce_b64"]),
                      base64.b64decode(_share_pkt["ciphertext_b64"]), None)

# 6. Protocollo: token, scheda, ricevuta
def _build_token():
    payload = {
        "pk_e_der_b64": base64.b64encode(
            _voter_pub.public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode(),
        "nonce":  _nonce.hex(),
        "ts":     time.time(),
        "ts_exp": time.time() + 3600,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = _ar_key.sign(hashlib.sha256(raw).digest(), padding.PKCS1v15(), hashes.SHA256())
    return {"payload": payload, "sig": base64.b64encode(sig).decode()}

_token_cache = _build_token()
def _verify_token():
    raw = json.dumps(_token_cache["payload"], sort_keys=True, separators=(",", ":")).encode()
    try:
        _ar_pub.verify(base64.b64decode(_token_cache["sig"]),
                       hashlib.sha256(raw).digest(),
                       padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        pass

def _build_ballot():
    commit = hashlib.sha256(bytes([_vote_bit]) + _r_commit).hexdigest()
    fields = {
        "c_voto_b64":  base64.b64encode(_c_voto).decode(),
        "commit_voto": commit,
        "token":       _token_cache,
        "ts_voto":     time.time(),
        "nonce_voto":  secrets.token_bytes(16).hex(),
    }
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    sig = _voter_key.sign(hashlib.sha256(raw).digest(), padding.PKCS1v15(), hashes.SHA256())
    return {**fields, "sigma_scheda_b64": base64.b64encode(sig).decode()}

_ballot_cache = _build_ballot()
def _verify_ballot():
    fields = {k: v for k, v in _ballot_cache.items() if k != "sigma_scheda_b64"}
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    try:
        _voter_pub.verify(base64.b64decode(_ballot_cache["sigma_scheda_b64"]),
                          hashlib.sha256(raw).digest(),
                          padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        pass

def _build_receipt():
    payload = {"ballot_hash": hashlib.sha256(b"test").hexdigest(),
               "seq_num": 1, "ts_reg": time.time()}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = _ar_key.sign(hashlib.sha256(raw).digest(), padding.PKCS1v15(), hashes.SHA256())
    return {"payload": payload, "sig": base64.b64encode(sig).decode()}

# 7. Certificati X.509
def _x509_issue():
    now = datetime.datetime.utcnow()
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST")])
    (x509.CertificateBuilder()
     .subject_name(subj).issuer_name(subj)
     .public_key(_voter_pub)
     .serial_number(x509.random_serial_number())
     .not_valid_before(now)
     .not_valid_after(now + datetime.timedelta(days=365))
     .sign(_ca_key, hashes.SHA256(), default_backend()))

# 8. Shamir (su campo piccolo per bench ripetibili)
_SMALL_P = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

def _miller_rabin(n, k=20):
    if n < 2: return False
    for sp in _SMALL_P:
        if n == sp: return True
        if n % sp == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0: r += 1; d //= 2
    for _ in range(k):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def _next_prime_gt(lower):
    c = lower + 1 + (lower % 2)
    while True:
        if all(c % sp != 0 for sp in _SMALL_P if sp < c):
            if _miller_rabin(c): return c
        c += 2

_S   = secrets.randbits(128)
_P   = _next_prime_gt(_S)
_a1  = secrets.randbelow(_P)
_shs = [(i, (_S + _a1 * i) % _P) for i in range(1, 4)]

def _shamir_split():
    a = secrets.randbelow(_P)
    [(i, (_S + a * i) % _P) for i in range(1, 4)]

def _lagrange():
    xs = [s[0] for s in _shs[:2]]; ys = [s[1] for s in _shs[:2]]
    sec = 0
    for i in range(2):
        num = den = 1
        for j in range(2):
            if i == j: continue
            num = (num * (-xs[j])) % _P
            den = (den * (xs[i] - xs[j])) % _P
        sec = (sec + ys[i] * num * pow(den, _P - 2, _P)) % _P

def _miller_rabin_bench():
    n = secrets.randbits(255) | 1
    _miller_rabin(n, k=20)

def _prime_search_256():
    _next_prime_gt(secrets.randbits(256))

# 9. Generazione chiave RSA-2048
def _rsa_keygen():
    rsa.generate_private_key(65537, RSA_BITS, default_backend())


# ── Esecuzione ────────────────────────────────────────────────────────────────

print("=" * 74)
print("  APS VOTING SYSTEM — Benchmark operazioni crittografiche")
print(f"  RSA: {RSA_BITS} bit  |  Modalità: {'FAST' if FAST_MODE else 'STANDARD'}")
print("=" * 74)
print(f"\n  {'Operazione':<54} {'Media':>9}   (min / max  n)")
print("  " + "-" * 70)

results = []

print("\n  [1] Hashing SHA-256")
results.append(run_bench("SHA-256 (64 byte)",                _sha256_64,       N_FAST))
results.append(run_bench("SHA-256 (100 KB)",                 _sha256_100k,     N_FAST))
results.append(run_bench("Commitment voto  SHA-256(v||r)",   _commit_vote,     N_FAST))

print("\n  [2] Firma digitale RSA-PKCS1v15 + SHA-256  (approssima FDH)")
results.append(run_bench("Firma  RSA-2048  (sk_AR / sk_e)",  _sign,            N_MED))
results.append(run_bench("Verifica firma  RSA-2048",         _verify,          N_MED))

print("\n  [3] Cifratura asimmetrica RSA-OAEP")
results.append(run_bench("Cifratura voto  RSA-OAEP (pk_AS)", _oaep_encrypt,    N_MED))
results.append(run_bench("Decifratura voto RSA-OAEP (sk_AS)",_oaep_decrypt,    N_MED))

print("\n  [4] Cifratura simmetrica AES-256-GCM")
results.append(run_bench("AES-256-GCM  cifratura (64 B)",    _aes_enc,         N_FAST))
results.append(run_bench("AES-256-GCM  decifratura (64 B)",  _aes_dec,         N_FAST))

print("\n  [5] Trasmissione sicura share  (RSA-OAEP + AES-GCM + firma)")
results.append(run_bench("Cifratura pacchetto share garante", _encrypt_share,   N_MED))
results.append(run_bench("Decifratura pacchetto share",       _decrypt_share,   N_MED))

print("\n  [6] Protocollo di voto: token — scheda — ricevuta")
results.append(run_bench("Costruzione token AR",              _build_token,     N_MED))
results.append(run_bench("Verifica token AR",                 _verify_token,    N_MED))
results.append(run_bench("Costruzione scheda + firma sk_e",   _build_ballot,    N_MED))
results.append(run_bench("Verifica firma scheda",             _verify_ballot,   N_MED))
results.append(run_bench("Costruzione ricevuta AR",           _build_receipt,   N_MED))

print("\n  [7] Infrastruttura PKI — certificati X.509")
results.append(run_bench("Emissione certificato X.509",       _x509_issue,      N_MED))

print("\n  [8] Schema di Shamir (t=2, n=3) su GF(p)")
results.append(run_bench("Shamir split  (128 bit, GF(p))",    _shamir_split,    N_FAST))
results.append(run_bench("Lagrange ricostruzione  (t=2)",     _lagrange,        N_FAST))
results.append(run_bench("Miller-Rabin  (256 bit, k=20)",     _miller_rabin_bench, N_MED))
results.append(run_bench("Ricerca primo p > S  (256 bit)",    _prime_search_256,   N_SLOW))

print("\n  [9] Generazione coppia di chiavi")
results.append(run_bench("Generazione coppia RSA-2048",       _rsa_keygen,      N_SLOW))

print("\n" + "=" * 74)

# ── Output JSON ───────────────────────────────────────────────────────────────

out = {
    "system":    "APS Voting System",
    "rsa_bits":  RSA_BITS,
    "fast_mode": FAST_MODE,
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    "results":   results,
}
with open("benchmark_results.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)

print(f"\n  Risultati salvati in: benchmark_results.json")
print(f"  Nota: tempi misurati in-process su macchina locale (single-thread).")
print(f"  Le operazioni di setup (keygen, Shamir) avvengono una tantum prima")
print(f"  dell'elezione e non impattano la latenza percepita dall'elettore.\n")
