"""
elettore.py — Client dell'Elettore.

Fasi implementate:
  keygen    — Generazione coppia di chiavi RSA locale       (Sezione 11.1)
  register  — Registrazione presso AA, ottenimento Cert_e   (Sezione 11.2-11.4)
  auth      — Autenticazione presso AR, ottenimento token   (Sezione 13)
  vote      — Espressione del voto, invio scheda ad AR      (Sezione 14)
  status    — Stato del wallet

Uso:
    python elettore.py keygen   <voter_id>
    python elettore.py register <voter_id>
    python elettore.py auth     <voter_id>
    python elettore.py vote     <voter_id> <0|1>
    python elettore.py status   <voter_id>
"""
import os, sys, json, time, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

import aa as aa_module
import ar as ar_module
from crypto_utils import (
    sign, sha256_bytes,
    b64e, canonical_bytes,
    encrypt_vote, commit_vote,
    build_ballot,
)
from config import WALLETS_DIR, RSA_KEY_SIZE


class Elettore:
    """
    Client dell'Elettore per il sistema di voto APS.

    Incapsula tutte le operazioni lato elettore: generazione chiavi locali,
    registrazione presso AA, autenticazione presso AR per il token di sessione,
    espressione del voto cifrato con impegno crittografico (commit), e
    consultazione dello stato del wallet locale.
    """

    def __init__(self, voter_id: str):
        """
        Inizializza l'istanza per un dato elettore.

        Args:
            voter_id: identificativo univoco dell'elettore (es. "MarioRossi001")
        """
        self.voter_id = voter_id

    # ── Path helpers ──────────────────────────────────────────────────────────

    def _wd(self) -> str:
        """Restituisce la directory wallet dell'elettore."""
        return os.path.join(WALLETS_DIR, self.voter_id)

    def _kp(self) -> str:
        """Percorso del file della chiave privata (sk_e)."""
        return os.path.join(self._wd(), "voter_key.pem")

    def _kpub(self) -> str:
        """Percorso del file della chiave pubblica (pk_e)."""
        return os.path.join(self._wd(), "voter_key_pub.pem")

    def _cp(self) -> str:
        """Percorso del file del certificato Cert_e."""
        return os.path.join(self._wd(), "voter_cert.pem")

    def _tp(self) -> str:
        """Percorso del file del token di sessione."""
        return os.path.join(self._wd(), "token.json")

    def _bp(self) -> str:
        """Percorso del file della scheda di voto."""
        return os.path.join(self._wd(), "ballot.json")

    def _rp(self) -> str:
        """Percorso del file della ricevuta."""
        return os.path.join(self._wd(), "receipt.json")

    def _mp(self) -> str:
        """Percorso del file dei metadati del wallet."""
        return os.path.join(self._wd(), "wallet_meta.json")

    # ── Wallet state helpers ──────────────────────────────────────────────────

    def _load_key(self):
        """Carica e restituisce la chiave privata sk_e del wallet."""
        with open(self._kp(), "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _meta(self) -> dict:
        """Carica e restituisce i metadati del wallet (dict vuoto se non esiste)."""
        if not os.path.exists(self._mp()):
            return {}
        with open(self._mp()) as f:
            return json.load(f)

    def _save_meta(self, m: dict) -> None:
        """Salva i metadati del wallet su disco."""
        with open(self._mp(), "w") as f:
            json.dump(m, f, indent=2)

    # ── Fase 1a: Generazione chiavi locali ────────────────────────────────────

    def keygen(self) -> None:
        """
        Genera (pk_e, sk_e) localmente (Sezione 11.1).
        sk_e non lascia mai il dispositivo dell'elettore.
        """
        if os.path.exists(self._kp()):
            print(f"[{self.voter_id}] Chiavi già generate.")
            return
        os.makedirs(self._wd(), exist_ok=True)
        print(f"[{self.voter_id}] Generazione coppia RSA-{RSA_KEY_SIZE}...")
        sk = rsa.generate_private_key(65537, RSA_KEY_SIZE, default_backend())
        pk = sk.public_key()
        with open(self._kp(), "wb") as f:
            f.write(sk.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        with open(self._kpub(), "wb") as f:
            f.write(pk.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        self._save_meta({
            "voter_id":   self.voter_id,
            "keygen":     True,
            "registered": False,
            "token":      False,
            "voted":      False,
        })
        print(f"[{self.voter_id}] Chiavi generate — sk_e in: {self._kp()}")

    # ── Fase 1b: Registrazione presso AA ─────────────────────────────────────

    def register(self) -> None:
        """
        Invia pk_e ad AA, riceve e verifica Cert_e (Sezioni 11.2-11.4).
        Salva Cert_e nel wallet locale.
        """
        meta = self._meta()
        if meta.get("registered"):
            print(f"[{self.voter_id}] ATTENZIONE: già registrato — ri-tentativo (la blockchain rifiuterà).")
        if not os.path.exists(self._kpub()):
            print(f"[{self.voter_id}] Esegui prima: python elettore.py keygen {self.voter_id}")
            sys.exit(1)

        print(f"\n[{self.voter_id}] === Registrazione presso AA ===")
        with open(self._kpub(), "rb") as f:
            pk_pem = f.read()

        cert_pem = aa_module.register_voter(self.voter_id, pk_pem)

        if not aa_module.verify_cert_e(cert_pem):
            raise ValueError(f"[{self.voter_id}] Cert_e ricevuto non verificabile!")

        with open(self._cp(), "wb") as f:
            f.write(cert_pem)
        cert = load_pem_x509_certificate(cert_pem)
        print(f"[{self.voter_id}] Cert_e verificato — valido fino: {cert.not_valid_after_utc}")

        meta["registered"] = True
        self._save_meta(meta)

    # ── Fase 3: Autenticazione e token ────────────────────────────────────────

    def auth(self) -> None:
        """
        Genera (nonce, ts), firma σ_e, invia (Cert_e, σ_e, nonce, ts) ad AR
        (Sezione 13). Riceve e salva il token di sessione nel wallet.
        """
        meta = self._meta()
        if not meta.get("registered"):
            print(f"[{self.voter_id}] Registrazione necessaria prima.")
            sys.exit(1)
        if meta.get("token"):
            print(f"[{self.voter_id}] ATTENZIONE: token già ottenuto — ri-tentativo (la blockchain rifiuterà).")

        print(f"\n[{self.voter_id}] === Autenticazione presso AR ===")

        # Sezione 13.1: genera nonce e ts
        nonce = secrets.token_bytes(16)
        ts    = time.time()

        # σ_e = Sign_ske(H(nonce || str(ts)))  — Eq. (4)
        sk_e    = self._load_key()
        sigma_e = sign(sk_e, sha256_bytes(nonce + str(ts).encode()))

        with open(self._cp(), "rb") as f:
            cert_e_pem = f.read()

        print(f"[{self.voter_id}] Invio (Cert_e, σ_e, nonce, ts) ad AR...")
        token = ar_module.request_token(cert_e_pem, sigma_e, nonce, ts)

        with open(self._tp(), "w") as f:
            json.dump(token, f, indent=2)
        print(f"[{self.voter_id}] Token salvato: {self._tp()}")

        meta["token"] = True
        self._save_meta(meta)

    # ── Fase 4: Espressione del voto ──────────────────────────────────────────

    def vote(self, choice: int) -> None:
        """
        Prepara e invia la scheda di voto (Sezione 14).

          1. C_voto      = EncOAEP_pkAS(v || r_voto)
          2. Commit_voto = SHA-256(v || r_commit)
          3. nonce_voto casuale
          4. σ_scheda    = Sign_ske(H(C_voto||Commit_voto||token||ts_voto||nonce_voto))
          5. Invia B ad AR → riceve Receipt e seq_num
          6. Salva (v, r_commit, B, Receipt, seq_num) localmente

        Args:
            choice: 1 per Sì, 0 per No
        """
        assert choice in (0, 1), "Il voto deve essere 0 (No) o 1 (Sì)"
        meta = self._meta()
        if not meta.get("token"):
            print(f"[{self.voter_id}] Autenticazione necessaria prima.")
            sys.exit(1)
        if meta.get("voted"):
            print(f"[{self.voter_id}] ATTENZIONE: voto già espresso — ri-tentativo (la blockchain rifiuterà).")

        print(f"\n[{self.voter_id}] === Espressione del voto ({'Sì' if choice else 'No'}) ===")

        # Carica pk_AS per cifratura RSA-OAEP
        import as_ as as_module
        pk_as = as_module.load_as_pubkey()

        with open(self._tp()) as f:
            token = json.load(f)
        sk_e = self._load_key()

        # 1. C_voto
        c_voto, r_voto = encrypt_vote(choice, pk_as)
        print(f"[{self.voter_id}] C_voto generato (RSA-OAEP).")

        # 2. Commit_voto
        commit_voto, r_commit = commit_vote(choice)
        print(f"[{self.voter_id}] Commit_voto = {commit_voto[:16]}...")

        # 3. nonce_voto + ts_voto
        nonce_voto = secrets.token_bytes(16)
        ts_voto    = time.time()

        # 4. Costruisce scheda e firma
        ballot, ballot_bytes = build_ballot(
            c_voto, commit_voto, token, ts_voto, nonce_voto, sk_e
        )
        print(f"[{self.voter_id}] Scheda firmata con sk_e.")

        # 5. Invia ad AR
        print(f"[{self.voter_id}] Invio scheda ad AR...")
        receipt, seq_num = ar_module.submit_ballot(ballot, ballot_bytes)

        # 6. Salvataggio locale per verifica individuale
        local_data = {
            "voter_id":  self.voter_id,
            "v":         choice,
            "r_commit":  r_commit.hex(),
            "r_voto":    r_voto.hex(),
            "seq_num":   seq_num,
            "ballot":    ballot,
            "receipt":   receipt,
        }
        with open(self._bp(), "w") as f:
            json.dump(local_data, f, indent=2)
        with open(self._rp(), "w") as f:
            json.dump(receipt, f, indent=2)

        print(f"[{self.voter_id}] Voto espresso — seqNum={seq_num}")
        print(f"[{self.voter_id}] Dati locali salvati per verifica individuale.")

        meta["voted"] = True
        self._save_meta(meta)

    # ── Stato wallet ──────────────────────────────────────────────────────────

    def status(self) -> None:
        """Stampa lo stato del wallet: keygen, registrazione, token, voto."""
        if not os.path.exists(self._wd()):
            print(f"[{self.voter_id}] Wallet non trovato.")
            return
        m   = self._meta()
        chk = lambda k: "✓" if m.get(k) else "✗"
        print(f"[{self.voter_id}]  Chiavi:{chk('keygen')}  "
              f"Cert_e:{chk('registered')}  "
              f"Token:{chk('token')}  "
              f"Voto:{chk('voted')}")
        if m.get("voted") and os.path.exists(self._bp()):
            with open(self._bp()) as f:
                bd = json.load(f)
            print(f"           seqNum={bd['seq_num']}, v={'Sì' if bd['v'] else 'No'}")


# ── Wrappers a livello modulo (compatibilità con gui.py, start_all.py, ecc.) ──

def keygen(voter_id: str) -> None:
    """Delega a Elettore.keygen()."""
    Elettore(voter_id).keygen()


def register(voter_id: str) -> None:
    """Delega a Elettore.register()."""
    Elettore(voter_id).register()


def auth(voter_id: str) -> None:
    """Delega a Elettore.auth()."""
    Elettore(voter_id).auth()


def vote(voter_id: str, choice: int) -> None:
    """Delega a Elettore.vote()."""
    Elettore(voter_id).vote(choice)


def status(voter_id: str) -> None:
    """Delega a Elettore.status()."""
    Elettore(voter_id).status()


def _meta(voter_id: str) -> dict:
    """Delega a Elettore._meta() — usato da gui.py per leggere lo stato del wallet."""
    return Elettore(voter_id)._meta()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python elettore.py <keygen|register|auth|vote|status> <voter_id> [0|1]")
        sys.exit(1)

    cmd, vid = sys.argv[1], sys.argv[2]
    if   cmd == "keygen":   keygen(vid)
    elif cmd == "register": register(vid)
    elif cmd == "auth":     auth(vid)
    elif cmd == "vote":
        if len(sys.argv) < 4:
            print("Specifica il voto: 0 (No) oppure 1 (Sì)")
            sys.exit(1)
        vote(vid, int(sys.argv[3]))
    elif cmd == "status":   status(vid)
    else:
        print(f"Comando sconosciuto: {cmd}")
        sys.exit(1)
