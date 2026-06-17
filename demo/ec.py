"""
ec.py — Ente Certificatore Legale (EC).

Conferisce valore legale ai momenti chiave dell'elezione (T.5):
  - Apertura urne: Att_apertura = Sign_skEC("APERTURA" || ts)
  - Chiusura urne: Att_chiusura = Sign_skEC("CHIUSURA" || ts)
  - Risultato:     Att_risultato = Sign_skEC("RISULTATO" || R || N || ts || MerkleRootBB)

Uso:
    python ec.py setup           — Inizializza EC (chiavi + certificato CA)
    python ec.py open-election   — Apre le urne on-chain
    python ec.py close-election  — Chiude le urne on-chain
    python ec.py status          — Mostra stato
"""

import os
import sys
import json
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

import ca as ca_module
import blockchain
from crypto_utils import sign, verify_sig, sha256_bytes, canonical_bytes, b64e, b64d
from config import (
    EC_DIR, EC_KEY_FILE, EC_CERT_FILE, CA_CERT_FILE,
    RSA_KEY_SIZE, ELECTION_ID,
)


class LegalCertificationEntity:
    """
    Ente Certificatore Legale (EC) del sistema di voto APS.

    Conferisce valore legale istituzionale all'apertura, alla chiusura e al
    risultato dell'elezione tramite attestazioni firmate con sk_EC.
    """

    def setup(self) -> None:
        """
        Inizializza EC:
          1. Genera coppia di chiavi RSA (sk_EC, pk_EC)
          2. Ottiene il certificato dalla CA
          3. Salva chiave e certificato su disco
        """
        if os.path.exists(EC_KEY_FILE):
            print("[EC] Setup già eseguito.")
            return
        if not os.path.exists(CA_CERT_FILE):
            print("[EC] Errore: CA non inizializzata. Esegui: python ca.py setup")
            sys.exit(1)

        os.makedirs(EC_DIR, exist_ok=True)
        print("[EC] Generazione coppia di chiavi RSA...")
        ec_key  = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
        ec_cert = ca_module.issue_authority_certificate(
            f"EC-{ELECTION_ID}", "Legal Certification Authority", ec_key.public_key()
        )
        with open(EC_KEY_FILE, "wb") as f:
            f.write(ec_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(EC_CERT_FILE, "wb") as f:
            f.write(ec_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[EC] Setup completato — Cert: {EC_CERT_FILE}")

    def attest_open(self) -> bytes:
        """
        Emette Att_apertura = Sign_skEC("APERTURA" || ts_apertura).
        Invoca VotingContract.openElection(ts, att) — Sezione 12.

        Returns:
            Attestazione di apertura serializzata in JSON (bytes)
        """
        ts      = time.time()
        payload = {"action": "APERTURA", "ts": ts}
        sig     = sign(self._load_key(), sha256_bytes(canonical_bytes(payload)))
        att     = json.dumps({"payload": payload, "sig": b64e(sig)}).encode()
        blockchain.open_election(ts, att)
        print(f"[EC] Att_apertura emessa — ts={int(ts)}")
        return att

    def attest_close(self) -> tuple:
        """
        Emette Att_chiusura = Sign_skEC("CHIUSURA" || ts_chiusura).
        Invoca VotingContract.closeElection(ts, att) — Sezione 15.1.

        Returns:
            (att_bytes, merkle_root_urna_hex)
        """
        ts      = time.time()
        payload = {"action": "CHIUSURA", "ts": ts}
        sig     = sign(self._load_key(), sha256_bytes(canonical_bytes(payload)))
        att     = json.dumps({"payload": payload, "sig": b64e(sig)}).encode()
        merkle_root = blockchain.close_election(ts, att)
        print(f"[EC] Att_chiusura emessa — ts={int(ts)}, MerkleRootUrna={merkle_root[:16]}...")
        return att, merkle_root

    def attest_result(self, result: int, total_votes: int, merkle_root_bb: str) -> bytes:
        """
        Emette Att_risultato = Sign_skEC("RISULTATO" || R || N || ts || MerkleRootBB).
        Sezione 16.2. Non invoca la blockchain direttamente (lo fa AS).

        Args:
            result:         numero di voti Sì (R)
            total_votes:    numero totale di schede (N)
            merkle_root_bb: radice Merkle del Bulletin Board (hex)

        Returns:
            Attestazione del risultato serializzata in JSON (bytes)
        """
        ts      = time.time()
        payload = {
            "action":         "RISULTATO",
            "result":         result,
            "total_votes":    total_votes,
            "ts":             ts,
            "merkle_root_bb": merkle_root_bb,
        }
        sig = sign(self._load_key(), sha256_bytes(canonical_bytes(payload)))
        att = json.dumps({"payload": payload, "sig": b64e(sig)}).encode()
        print(f"[EC] Att_risultato emessa — R={result}/{total_votes}")
        return att

    def declare_scrutiny_overdue(self) -> None:
        """
        Invoca VotingContract.declareScrutinyOverdue() se la deadline è trascorsa.
        Transita il contratto da CLOSED a SCRUTINY_OVERDUE — Sezione CRITICA-5.
        """
        blockchain.declare_scrutiny_overdue()
        print(f"[EC] ScrutinyOverdue dichiarato — AS non ha pubblicato entro la deadline.")

    def verify_att(self, att_bytes: bytes, expected_action: str) -> bool:
        """
        Verifica un'attestazione EC: controlla firma e corrispondenza dell'azione.

        Args:
            att_bytes:       attestazione serializzata in JSON (bytes)
            expected_action: azione attesa (es. "RISULTATO")

        Returns:
            True se la firma è valida e l'azione corrisponde
        """
        try:
            obj     = json.loads(att_bytes)
            payload = obj["payload"]
            sig     = b64d(obj["sig"])
            if payload.get("action") != expected_action:
                return False
            return verify_sig(
                self.load_pubkey(),
                sha256_bytes(canonical_bytes(payload)),
                sig,
            )
        except Exception:
            return False

    def load_pubkey(self):
        """Restituisce la chiave pubblica EC (pk_EC) estratta dal certificato."""
        return load_pem_x509_certificate(self.load_cert_pem()).public_key()

    def load_cert_pem(self) -> bytes:
        """Restituisce il certificato EC in formato PEM (bytes)."""
        with open(EC_CERT_FILE, "rb") as f:
            return f.read()

    def _load_key(self) -> rsa.RSAPrivateKey:
        """Carica la chiave privata EC dal disco (uso interno)."""
        with open(EC_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)


# ── Wrappers a livello modulo (compatibilità con gli altri moduli) ─────────────

def setup() -> None:
    """Delega a LegalCertificationEntity.setup()."""
    LegalCertificationEntity().setup()


def attest_open() -> bytes:
    """Delega a LegalCertificationEntity.attest_open()."""
    return LegalCertificationEntity().attest_open()


def attest_close() -> tuple:
    """Delega a LegalCertificationEntity.attest_close()."""
    return LegalCertificationEntity().attest_close()


def attest_result(result: int, total_votes: int, merkle_root_bb: str) -> bytes:
    """Delega a LegalCertificationEntity.attest_result()."""
    return LegalCertificationEntity().attest_result(result, total_votes, merkle_root_bb)


def declare_scrutiny_overdue() -> None:
    """Delega a LegalCertificationEntity.declare_scrutiny_overdue()."""
    LegalCertificationEntity().declare_scrutiny_overdue()


def verify_att(att_bytes: bytes, expected_action: str) -> bool:
    """Delega a LegalCertificationEntity.verify_att()."""
    return LegalCertificationEntity().verify_att(att_bytes, expected_action)


def load_ec_cert_pem() -> bytes:
    """Delega a LegalCertificationEntity.load_cert_pem()."""
    return LegalCertificationEntity().load_cert_pem()


def load_ec_pubkey():
    """Delega a LegalCertificationEntity.load_pubkey()."""
    return LegalCertificationEntity().load_pubkey()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cmds = {
        "setup":          "Inizializza EC",
        "open-election":  "Apre le urne on-chain",
        "close-election": "Chiude le urne on-chain",
        "status":         "Mostra stato",
    }
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print("Uso: python ec.py <comando>")
        for cmd, desc in cmds.items():
            print(f"  {cmd:<18} {desc}")
        sys.exit(1)

    ec_auth = LegalCertificationEntity()
    cmd     = sys.argv[1]

    if   cmd == "setup":          ec_auth.setup()
    elif cmd == "open-election":  ec_auth.attest_open()
    elif cmd == "close-election": ec_auth.attest_close()
    elif cmd == "status":
        if not os.path.exists(EC_CERT_FILE):
            print("[EC] Non inizializzata.")
        else:
            cert = load_pem_x509_certificate(ec_auth.load_cert_pem())
            print(f"[EC] Subject:    {cert.subject.rfc4514_string()}")
            print(f"[EC] Valido fino:{cert.not_valid_after_utc}")
            print(f"[EC] Stato contr:{blockchain.get_state()}")
