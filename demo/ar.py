"""
ar.py — Autorità di Raccolta (AR).

Responsabile di:
  - Autenticazione elettori e rilascio token di sessione (Sezione 13)
  - Ricezione, verifica e ancoraggio schede di voto (Sezione 14.2.2)
  - Rilascio ricevute agli elettori

Uso:
    python ar.py setup   — Inizializza AR
    python ar.py status  — Stato AR
"""

import os
import sys
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

import ca as ca_module
import blockchain
from crypto_utils import (
    verify_sig, sha256_bytes,
    b64d, hash_cert, hash_token, hash_ballot,
    build_token, build_receipt,
    verify_token, extract_pk_e_from_token,
    verify_ballot_signature, token_to_bytes,
)
import aa as aa_module
from config import (
    AR_DIR, AR_KEY_FILE, AR_CERT_FILE, CA_CERT_FILE,
    RSA_KEY_SIZE, ELECTION_ID, TOKEN_LIFETIME, REPLAY_WINDOW,
)

# Registro anti-replay a livello processo (condiviso da tutte le istanze AR).
# Mantiene la stessa semantica del modulo originale (variabile module-level),
# accessibile da gui.py tramite ar._used_nonces per il reset.
_used_nonces: set = set()


class CollectionAuthority:
    """
    Autorità di Raccolta (AR) del sistema di voto APS.

    Autentica gli elettori, rilascia token di sessione monouso e raccoglie
    le schede di voto ancorandole on-chain con i relativi commitment.
    Il registro anti-replay _used_nonces è condiviso a livello processo.
    """

    def setup(self) -> None:
        """
        Inizializza AR:
          1. Genera coppia di chiavi RSA (sk_AR, pk_AR)
          2. Ottiene il certificato dalla CA
          3. Salva chiave e certificato su disco
        """
        if os.path.exists(AR_KEY_FILE):
            print("[AR] Setup già eseguito.")
            return
        if not os.path.exists(CA_CERT_FILE):
            print("[AR] Errore: CA non inizializzata.")
            sys.exit(1)

        os.makedirs(AR_DIR, exist_ok=True)
        print("[AR] Generazione coppia di chiavi RSA...")
        ar_key  = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
        ar_cert = ca_module.issue_authority_certificate(
            f"AR-{ELECTION_ID}", "Collection Authority", ar_key.public_key()
        )
        with open(AR_KEY_FILE, "wb") as f:
            f.write(ar_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(AR_CERT_FILE, "wb") as f:
            f.write(ar_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[AR] Setup completato — Cert: {AR_CERT_FILE}")

    def request_token(
        self,
        cert_e_pem: bytes,
        sigma_e: bytes,
        nonce: bytes,
        ts: float,
    ) -> dict:
        """
        Valida la richiesta dell'elettore ed emette il token di sessione.

        Flusso (Sezione 13.3-13.4):
          1. Verifica autenticità Cert_e      (firma AA)
          2. Verifica firma σ_e               (freschezza + autenticità)
          3. Controllo anti-replay            (nonce + finestra 5 min)
          4. issueToken on-chain              (anti-emissione-multipla)
          5. Token = Sign_skAR(pk_e || nonce || ts || ts_exp)

        Args:
            cert_e_pem: certificato elettore in PEM
            sigma_e:    firma σ_e = Sign_ske(H(nonce || str(ts)))
            nonce:      nonce casuale 128-bit dell'elettore
            ts:         timestamp della richiesta

        Returns:
            Token di sessione come dict firmato da AR
        """
        print(f"\n[AR] === Rilascio token ===")

        # 1. Verifica Cert_e
        if not aa_module.verify_cert_e(cert_e_pem):
            raise ValueError("[AR] RIFIUTATO: Cert_e non autentico.")
        pk_e = aa_module.extract_voter_pubkey(cert_e_pem)
        print(f"[AR] Cert_e verificato.")

        # 2. Verifica σ_e = Sign_ske(H(nonce || str(ts)))  — Eq. (4)
        h_payload = sha256_bytes(nonce + str(ts).encode())
        if not verify_sig(pk_e, h_payload, sigma_e):
            raise ValueError("[AR] RIFIUTATO: firma σ_e non valida.")
        print(f"[AR] Firma σ_e verificata.")

        # 3. Anti-replay
        nonce_hex = nonce.hex()
        if nonce_hex in _used_nonces:
            raise ValueError("[AR] RIFIUTATO: nonce già utilizzato (replay).")
        now = time.time()
        if abs(now - ts) > REPLAY_WINDOW:
            raise ValueError(f"[AR] RIFIUTATO: timestamp fuori finestra (Δ={abs(now-ts):.0f}s).")
        _used_nonces.add(nonce_hex)
        print(f"[AR] Anti-replay OK.")

        # 4. issueToken on-chain
        cert_hash = hash_cert(cert_e_pem)
        blockchain.issue_token(cert_hash)

        # 5. Costruzione token
        ts_exp = now + TOKEN_LIFETIME
        token  = build_token(pk_e, nonce, now, ts_exp, self._load_key())
        print(f"[AR] Token emesso — ts_exp={int(ts_exp)}")
        return token

    def submit_ballot(self, ballot: dict, ballot_bytes: bytes) -> tuple:
        """
        Verifica la scheda e la ancora on-chain.

        Flusso corretto (Sezione 14.2.2) — tutte le verifiche off-chain prima
        di qualsiasi operazione on-chain per prevenire attacchi DoS:
          1. Verifica firma AR sul token          (off-chain)
          2. Verifica scadenza token ts_exp       (off-chain)
          3. Estrae pk_e dal token e verifica σ_scheda (off-chain)
          4. Verifica freschezza (ts_voto, nonce_voto) (off-chain)
          5. consumeToken on-chain
          6. submitBallotAnchor on-chain
          7. Emette Receipt firmata

        Args:
            ballot:       scheda di voto come dict
            ballot_bytes: serializzazione canonica della scheda (per hashing)

        Returns:
            (receipt dict, seq_num int)
        """
        print(f"\n[AR] === Verifica e ancoraggio scheda ===")

        token      = ballot["token"]
        token_hash = hash_token(token_to_bytes(token))

        # 1. Verifica firma AR sul token (off-chain)
        if not verify_token(token, self.load_pubkey()):
            raise ValueError("[AR] RIFIUTATO: firma AR sul token non valida.")

        # 2. Verifica scadenza token ts_exp (off-chain) — CRITICA-8
        if time.time() > token["payload"]["ts_exp"]:
            raise ValueError("[AR] RIFIUTATO: token scaduto (ts_exp superato).")

        # 3. Estrae pk_e dal token e verifica σ_scheda (off-chain)
        pk_e = extract_pk_e_from_token(token)
        if not verify_ballot_signature(ballot, pk_e):
            raise ValueError("[AR] RIFIUTATO: σ_scheda non valida.")
        print(f"[AR] Firma scheda verificata.")

        # 4. Freschezza ts_voto e nonce_voto (off-chain)
        ts_voto    = ballot["ts_voto"]
        nonce_voto = ballot["nonce_voto"]
        if abs(time.time() - ts_voto) > REPLAY_WINDOW:
            raise ValueError("[AR] RIFIUTATO: ts_voto fuori finestra.")
        if nonce_voto in _used_nonces:
            raise ValueError("[AR] RIFIUTATO: nonce_voto già usato.")
        _used_nonces.add(nonce_voto)
        print(f"[AR] Freschezza scheda verificata.")

        # 5. consumeToken on-chain — solo dopo tutti i controlli off-chain
        blockchain.consume_token(token_hash)
        print(f"[AR] Token consumato on-chain.")

        # 6. submitBallotAnchor on-chain
        ballot_hash = hash_ballot(ballot_bytes)
        commit_voto = ballot["commit_voto"]
        c_voto      = b64d(ballot["c_voto_b64"])
        ts_reg      = time.time()
        seq_num     = blockchain.submit_ballot_anchor(
            token_hash, ballot_hash, commit_voto, c_voto, ts_reg
        )

        # 7. Receipt — firmata solo dopo la conferma on-chain
        receipt = build_receipt(ballot_hash, seq_num, ts_reg, self._load_key())
        print(f"[AR] Receipt emessa — seqNum={seq_num}, H(B)={ballot_hash[:16]}...")
        return receipt, seq_num

    def load_pubkey(self):
        """Restituisce la chiave pubblica AR (pk_AR) estratta dal certificato."""
        return load_pem_x509_certificate(self.load_cert_pem()).public_key()

    def load_cert_pem(self) -> bytes:
        """Restituisce il certificato AR in formato PEM (bytes)."""
        with open(AR_CERT_FILE, "rb") as f:
            return f.read()

    def _load_key(self) -> rsa.RSAPrivateKey:
        """Carica la chiave privata AR dal disco (uso interno)."""
        with open(AR_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)


# ── Wrappers a livello modulo (compatibilità con gli altri moduli) ─────────────

def setup() -> None:
    """Delega a CollectionAuthority.setup()."""
    CollectionAuthority().setup()


def request_token(cert_e_pem: bytes, sigma_e: bytes, nonce: bytes, ts: float) -> dict:
    """Delega a CollectionAuthority.request_token()."""
    return CollectionAuthority().request_token(cert_e_pem, sigma_e, nonce, ts)


def submit_ballot(ballot: dict, ballot_bytes: bytes) -> tuple:
    """Delega a CollectionAuthority.submit_ballot()."""
    return CollectionAuthority().submit_ballot(ballot, ballot_bytes)


def load_ar_pubkey():
    """Delega a CollectionAuthority.load_pubkey()."""
    return CollectionAuthority().load_pubkey()


def load_ar_cert_pem() -> bytes:
    """Delega a CollectionAuthority.load_cert_pem()."""
    return CollectionAuthority().load_cert_pem()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cmds = {"setup": "Inizializza AR", "status": "Mostra stato AR"}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print("Uso: python ar.py <setup|status>")
        sys.exit(1)

    ar_auth = CollectionAuthority()

    if sys.argv[1] == "setup":
        ar_auth.setup()
    elif sys.argv[1] == "status":
        if not os.path.exists(AR_CERT_FILE):
            print("[AR] Non inizializzata.")
        else:
            print(f"[AR] Cert:            {AR_CERT_FILE}")
            print(f"[AR] Stato contratto: {blockchain.get_state()}")
            print(f"[AR] Schede ancorate: {blockchain.get_ballot_count()}")
