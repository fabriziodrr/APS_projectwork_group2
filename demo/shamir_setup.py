"""
shamir_setup.py — Schema di Shamir (t=2, n=3) per la chiave di decifratura AS.

Implementa il protocollo descritto nella Sezione 10.4 del documento teorico.

FASE DI SETUP  (chiamata da as_.setup):
  1. Genera (pk_AS, sk_AS) per cifratura/decifratura voti
  2. Estrae d = esponente privato RSA di sk_AS  →  segreto intero S
     Nota: d è il nucleo segreto di RSA; gli altri parametri (p, q, dp, dq)
     si ricostruiscono a partire da (d, n, e) tramite fattorizzazione.
  3. Genera primo p > d usando Miller-Rabin (aritmetica pura Python, nessuna
     dipendenza esterna oltre a `secrets` e `math` della stdlib).
  4. Polinomio casuale f(x) = d + a1·x  mod p  (t=2, grado 1; a1 ∈ GF(p))
  5. 3 share: si = f(i),  i = 1, 2, 3
  6. Distrugge d e il polinomio dalla memoria (del + azzeramento)
  7. Salva share_1.json, share_2.json, share_3.json — sk_AS MAI su disco
  8. Salva il solo certificato pk_AS (pubblica, usata da elettore.py)
  9. Genera (pk_AS_sign, sk_AS_sign) — chiave di firma BB, mai distribuita

FASE DI SCRUTINIO  (chiamata da as_.tally):
  • reconstruct_dec_key(share_paths) → RSAPrivateKey
      1. Legge ≥ t=2 share dai file indicati
      2. Lagrange su GF(p)  →  d
      3. Carica n, e dal certificato AS_CERT_FILE (pubblica)
      4. Fattorizza n con l'algoritmo probabilistico di Miller-Rabin
         che sfrutta k = d·e − 1 = multiplo di λ(n)
      5. Ricostruisce l'oggetto RSAPrivateKey completo (con parametri CRT)
      La chiave NON viene mai scritta su disco; la distruzione è
      responsabilità del chiamante (as_.tally: del sk_as).
"""

import os
import sys
import json
import math
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_iqmp,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
)
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

import ca as ca_module
from config import (
    AS_DIR,
    AS_CERT_FILE,
    AS_SIGN_KEY_FILE,
    AS_SIGN_CERT_FILE,
    AS_RECV_KEY_FILE,
    AS_RECV_CERT_FILE,
    CA_CERT_FILE,
    RSA_KEY_SIZE,
    ELECTION_ID,
    SHARE_1_PATH,
    SHARE_2_PATH,
    SHARE_3_PATH,
    GUARDIAN_1_KEY_FILE, GUARDIAN_2_KEY_FILE, GUARDIAN_3_KEY_FILE,
    GUARDIAN_1_CERT_FILE, GUARDIAN_2_CERT_FILE, GUARDIAN_3_CERT_FILE,
)


# ── Test di primalità Miller-Rabin (pura Python) ─────────────────────────────

# Primi piccoli per trial-division rapida (elimina ~60% dei candidati)
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
]


def _miller_rabin(n: int, k: int = 20) -> bool:
    """
    Test di primalità probabilistico Miller-Rabin con k testimoni casuali.
    Probabilità di falso-positivo: ≤ 4^{-k}.  Con k=20: ≤ 10^{-12}.
    Corrisponde alla fase di verifica primaria dei candidati p in Shamir.
    """
    if n < 2:
        return False
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    # Scrive n−1 = 2^r · d_odd  (d_odd dispari)
    r, d_odd = 0, n - 1
    while d_odd % 2 == 0:
        r += 1
        d_odd //= 2
    for _ in range(k):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d_odd, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _next_prime_gt(lower: int) -> int:
    """
    Restituisce il più piccolo primo p > lower usando ricerca sequenziale
    con trial-division + Miller-Rabin.  Gap medio vicino a 2^2048 ≈ 1420.
    """
    candidate = lower + 1
    if candidate % 2 == 0:
        candidate += 1
    while True:
        if all(candidate % sp != 0 for sp in _SMALL_PRIMES if sp < candidate):
            if _miller_rabin(candidate):
                return candidate
        candidate += 2


# ── Schema di Shamir (t, n) su GF(p) ─────────────────────────────────────────

def _shamir_split(S: int, t: int, n: int, p: int) -> list:
    """
    Fase di Setup — Shamir (t, n):
    Divide il segreto S in n share con soglia t su GF(p).
    Polinomio:  f(x) = S + a1·x + … + a_{t-1}·x^{t-1}  mod p
    Ritorna la lista [(x_i, f(x_i)) per i = 1…n].
    """
    coeffs = [S] + [secrets.randbelow(p) for _ in range(t - 1)]
    shares = []
    for i in range(1, n + 1):
        yi = sum(coeffs[j] * pow(i, j, p) for j in range(t)) % p
        shares.append((i, yi))
    return shares


def _lagrange_reconstruct(shares: list, p: int) -> int:
    """
    Fase di Scrutinio — Interpolazione di Lagrange su GF(p):
    Ricostruisce f(0) da almeno t share.
    f(0) = Σ_i  y_i · L_i(0)  mod p
    L_i(0) = Π_{j≠i} (−x_j) / (x_i − x_j)  mod p
    L'inverso modulare si calcola con il piccolo teorema di Fermat:
    a^{−1} ≡ a^{p−2}  (mod p)  (valido perché p è primo).
    """
    xs = [s[0] for s in shares]
    ys = [s[1] for s in shares]
    secret = 0
    for i in range(len(shares)):
        num = 1
        den = 1
        for j in range(len(shares)):
            if i == j:
                continue
            num = (num * (-xs[j])) % p
            den = (den * (xs[i] - xs[j])) % p
        li = num * pow(den, p - 2, p) % p
        secret = (secret + ys[i] * li) % p
    return secret


# ── Ricostruzione chiave RSA da d ─────────────────────────────────────────────

def _factor_rsa_modulus(n: int, e: int, d: int) -> tuple:
    """
    Fattorizza n dato (e, d) tramite l'algoritmo probabilistico che sfrutta
    k = d·e − 1 = multiplo di λ(n) = lcm(p−1, q−1).
    Scrive k = 2^r · t  (t dispari); per un a casuale, calcola a^t mod n
    e risale alla radice quadrata di 1 diversa da ±1.
    Probabilità di successo per tentativo: ≥ 1/2.
    """
    k = d * e - 1
    r, t = 0, k
    while t % 2 == 0:
        r += 1
        t //= 2
    for _ in range(200):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, t, n)
        if x in (1, n - 1):
            continue
        for _ in range(r):
            y = pow(x, 2, n)
            if y == 1:
                g = math.gcd(x - 1, n)
                if 1 < g < n:
                    return g, n // g
                break
            x = y
            if x == n - 1:
                break
    raise ValueError("[AS-Shamir] Fattorizzazione n fallita: parametri RSA incoerenti.")


def _build_private_key(d: int, n: int, e: int) -> rsa.RSAPrivateKey:
    """
    Ricostruisce l'oggetto RSAPrivateKey completo da (d, n, e):
      1. Fattorizza n → p_rsa, q_rsa
      2. Calcola parametri CRT: dp, dq, qinv
      3. Assembla RSAPrivateNumbers e restituisce la chiave
    """
    p_rsa, q_rsa = _factor_rsa_modulus(n, e, d)
    if p_rsa < q_rsa:
        p_rsa, q_rsa = q_rsa, p_rsa
    dp   = rsa_crt_dmp1(d, p_rsa)
    dq   = rsa_crt_dmq1(d, q_rsa)
    qinv = rsa_crt_iqmp(p_rsa, q_rsa)
    pub  = RSAPublicNumbers(e, n)
    priv = RSAPrivateNumbers(p_rsa, q_rsa, d, dp, dq, qinv, pub)
    return priv.private_key(default_backend())


class ShamirScheme:
    """
    Classe di supporto che incapsula lo schema di Shamir (t=2, n=3)
    per la gestione della chiave di decifratura AS.

    Fornisce le operazioni di setup (generazione e distribuzione delle share)
    e di ricostruzione (interpolazione di Lagrange per riottenere sk_AS).
    Le funzioni matematiche pure (_miller_rabin, _shamir_split, ecc.) rimangono
    a livello modulo e vengono riutilizzate da questa classe.
    """

    def setup(self) -> None:
        """
        Fase di Setup Shamir — Sezione 10.4:
          1. Genera (pk_AS, sk_AS) RSA per la cifratura dei voti
          2. Estrae l'esponente privato d da sk_AS  →  segreto S
          3. Genera primo p > d con Miller-Rabin (pura Python stdlib)
          4. Applica Shamir (t=2, n=3): f(x) = S + a1·x  mod p, a1 casuale
          5. Distrugge S = d e il polinomio dalla memoria
          6. Salva share_1.json, share_2.json, share_3.json — sk_AS MAI su disco
          7. Salva solo il certificato pk_AS (pubblica, per cifratura voti)
          8. Genera (pk_AS_sign, sk_AS_sign) — firma BB, mai distribuita né distrutta
          9. Genera (pk_AS_recv, sk_AS_recv) — ricezione share cifrate dai garanti
         10. Genera chiavi dei 3 garanti (G1, G2, G3)
        """
        if os.path.exists(AS_CERT_FILE):
            print("[AS] Setup già eseguito.")
            return
        if not os.path.exists(CA_CERT_FILE):
            print("[AS] Errore: CA non inizializzata.")
            sys.exit(1)

        os.makedirs(AS_DIR, exist_ok=True)

        # 1. Genera (pk_AS, sk_AS)
        print("[AS] Generazione chiave di decifratura (pk_AS, sk_AS)…")
        sk_as   = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
        as_cert = ca_module.issue_authority_certificate(
            f"AS-{ELECTION_ID}", "Scrutiny Authority", sk_as.public_key()
        )

        # 2. Estrae l'esponente privato d (segreto S per Shamir)
        d = sk_as.private_numbers().d
        print(f"[AS] Esponente privato d estratto: {d.bit_length()} bit")

        # 3. Genera primo p > d
        print("[AS] Generazione primo p > d con Miller-Rabin — attendere…")
        p = _next_prime_gt(d)
        print(f"[AS] Primo p trovato: {p.bit_length()} bit")

        # 4. Schema Shamir (t=2, n=3): f(x) = d + a1·x  mod p
        shares = _shamir_split(d, t=2, n=3, p=p)
        print(f"[AS] Schema Shamir (2,3) completato — 3 share generate.")

        # 5. Distrugge d e sk_as dalla memoria (simbolico in Python)
        d = 0
        del d, sk_as

        # 6. Salva le 3 share nei file dei garanti
        share_paths = [SHARE_1_PATH, SHARE_2_PATH, SHARE_3_PATH]
        for idx, (garante_id, sv) in enumerate(shares):
            data = {
                "garante_id":  garante_id,
                "share":       str(sv),
                "prime":       str(p),
                "election_id": ELECTION_ID,
            }
            with open(share_paths[idx], "w") as f:
                json.dump(data, f, indent=2)
            print(f"[AS] Share garante_{garante_id} → {share_paths[idx]}")
        print("[AS] sk_AS NON scritta su disco — distribuita via Shamir (2,3).")

        # 7. Salva il certificato pk_AS
        with open(AS_CERT_FILE, "wb") as f:
            f.write(as_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[AS] Certificato pk_AS salvato: {AS_CERT_FILE}")

        # 8. Genera (pk_AS_sign, sk_AS_sign) — firma BB, mai distribuita
        print("[AS] Generazione chiave di firma (pk_AS_sign, sk_AS_sign)…")
        sk_sign   = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
        sign_cert = ca_module.issue_authority_certificate(
            f"AS-SIGN-{ELECTION_ID}", "Scrutiny Authority Signing", sk_sign.public_key()
        )
        with open(AS_SIGN_KEY_FILE, "wb") as f:
            f.write(sk_sign.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(AS_SIGN_CERT_FILE, "wb") as f:
            f.write(sign_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[AS] Chiave firma salvata: {AS_SIGN_KEY_FILE}")

        # 9. Genera (pk_AS_recv, sk_AS_recv) — ricezione share cifrate dai garanti
        print("[AS] Generazione chiave di ricezione share (pk_AS_recv, sk_AS_recv)…")
        sk_recv   = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
        recv_cert = ca_module.issue_authority_certificate(
            f"AS-RECV-{ELECTION_ID}", "Scrutiny Authority Recv", sk_recv.public_key()
        )
        with open(AS_RECV_KEY_FILE, "wb") as f:
            f.write(sk_recv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(AS_RECV_CERT_FILE, "wb") as f:
            f.write(recv_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[AS] Chiave ricezione share salvata: {AS_RECV_KEY_FILE}")

        # 10. Genera chiavi dei garanti (G1, G2, G3)
        guardian_key_files  = [GUARDIAN_1_KEY_FILE,  GUARDIAN_2_KEY_FILE,  GUARDIAN_3_KEY_FILE]
        guardian_cert_files = [GUARDIAN_1_CERT_FILE, GUARDIAN_2_CERT_FILE, GUARDIAN_3_CERT_FILE]
        for gid, (kf, cf) in enumerate(zip(guardian_key_files, guardian_cert_files), start=1):
            sk_g   = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
            g_cert = ca_module.issue_authority_certificate(
                f"GUARDIAN-{gid}-{ELECTION_ID}", f"Guardian {gid}", sk_g.public_key()
            )
            with open(kf, "wb") as f:
                f.write(sk_g.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))
            with open(cf, "wb") as f:
                f.write(g_cert.public_bytes(serialization.Encoding.PEM))
            print(f"[AS] Chiave garante_{gid} salvata: {kf}")

        print(f"[AS] Setup completato. sk_AS mai su disco — solo le share sono distribuite.")

    def reconstruct_dec_key_from_data(
        self,
        share_tuples: list,
        prime: int,
    ) -> rsa.RSAPrivateKey:
        """
        Ricostruisce sk_AS da share già validate e decifrate (usato da tally()).
        La chiave NON viene mai scritta su disco.

        Args:
            share_tuples: lista di (garante_id: int, share_value: int) — almeno t=2 elementi
            prime:        il campo GF(p) usato durante il setup Shamir

        Returns:
            RSAPrivateKey di AS, pronta per la decifratura
        """
        if len(share_tuples) < 2:
            raise ValueError("[AS-Shamir] Servono almeno t=2 share per la ricostruzione.")

        print(f"[AS-Shamir] Interpolazione di Lagrange su GF(p), |p|={prime.bit_length()} bit …")
        d = _lagrange_reconstruct(share_tuples, prime)

        with open(AS_CERT_FILE, "rb") as f:
            cert = load_pem_x509_certificate(f.read())
        pub_numbers  = cert.public_key().public_numbers()
        n_mod, e_exp = pub_numbers.n, pub_numbers.e

        print(f"[AS-Shamir] d ricostruito — fattorizzazione modulo RSA in corso …")
        sk = _build_private_key(d, n_mod, e_exp)

        d = 0
        del d, pub_numbers, n_mod, e_exp

        print(f"[AS-Shamir] sk_AS ricostruita in memoria — pronta per la decifratura.")
        return sk

    def reconstruct_dec_key(self, share_paths: list) -> rsa.RSAPrivateKey:
        """
        Ricostruisce sk_AS leggendo le share dai file indicati.
        Wrapper di reconstruct_dec_key_from_data — usato nei test diretti.

        Args:
            share_paths: lista di almeno 2 path a file share_X.json

        Returns:
            RSAPrivateKey di AS ricostruita in memoria
        """
        if len(share_paths) < 2:
            raise ValueError("[AS-Shamir] Servono almeno t=2 share per la ricostruzione.")

        loaded = []
        prime  = None
        for path in share_paths:
            with open(path) as f:
                data = json.load(f)
            gid   = int(data["garante_id"])
            sv    = int(data["share"])
            p_val = int(data["prime"])
            if prime is None:
                prime = p_val
            elif prime != p_val:
                raise ValueError(
                    f"[AS-Shamir] Incoerenza: prime diversi tra le share ({path})."
                )
            loaded.append((gid, sv))
            print(f"[AS-Shamir] Share garante_{gid} caricata da {os.path.basename(path)}")

        return self.reconstruct_dec_key_from_data(loaded, prime)


# ── Wrappers a livello modulo (compatibilità con as_.py e test diretti) ────────

def setup() -> None:
    """Delega a ShamirScheme.setup()."""
    ShamirScheme().setup()


def reconstruct_dec_key_from_data(share_tuples: list, prime: int) -> rsa.RSAPrivateKey:
    """Delega a ShamirScheme.reconstruct_dec_key_from_data()."""
    return ShamirScheme().reconstruct_dec_key_from_data(share_tuples, prime)


def reconstruct_dec_key(share_paths: list) -> rsa.RSAPrivateKey:
    """Delega a ShamirScheme.reconstruct_dec_key()."""
    return ShamirScheme().reconstruct_dec_key(share_paths)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ShamirScheme().setup()
