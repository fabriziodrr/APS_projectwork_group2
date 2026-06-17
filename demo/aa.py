"""
aa.py — Autorità di Autenticazione (AA).

Responsabile di:
  - Setup: generazione chiavi RSA, ottenimento certificato da CA
  - Registrazione elettori: verifica identità, registrazione on-chain,
    emissione di Cert_e = Sign_skAA(pk_e || ID_elettore)

Il ruolo di AA termina nel momento in cui l'elettore ottiene il token
di sessione da AR. AA non partecipa alle fasi di votazione né di scrutinio.

Uso:
    python aa.py setup                        — Inizializza AA
    python aa.py register <voter_id>          — Registra un elettore
    python aa.py status                       — Mostra stato AA
    python aa.py list-voters                  — Elenca gli elettori registrati
"""

import os
import sys
import json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

import blockchain
import ca as ca_module
from config import (
    AA_DIR, AA_KEY_FILE, AA_CERT_FILE,
    CA_CERT_FILE, WALLETS_DIR, AUTHORIZED_VOTERS_FILE,
    RSA_KEY_SIZE, ELECTION_ID, PKI_DIR,
)


class AuthenticationAuthority:
    """
    Autorità di Autenticazione (AA) del sistema di voto APS.

    Verifica l'identità degli elettori e ne emette i certificati
    Cert_e = Sign_skAA(pk_e || ID_elettore). Gestisce la lista degli
    aventi diritto al voto e la registrazione anti-duplicato on-chain.
    """

    def setup(self) -> None:
        """
        Inizializza l'AA:
          1. Genera coppia di chiavi RSA (sk_AA, pk_AA)
          2. Richiede il certificato a CA — CertAA = Sign_skCA(pk_AA || IDAA)
          3. Salva chiave privata e certificato su disco

        Precondizione: CA già inizializzata (python ca.py setup)
        """
        if os.path.exists(AA_KEY_FILE):
            print("[AA] Setup già eseguito. Usa 'status' per verificare.")
            return
        if not os.path.exists(CA_CERT_FILE):
            print("[AA] Errore: CA non inizializzata. Esegui prima: python ca.py setup")
            sys.exit(1)

        os.makedirs(AA_DIR, exist_ok=True)

        print("[AA] Generazione coppia di chiavi RSA...")
        aa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend(),
        )

        print("[AA] Richiesta certificato alla CA...")
        aa_cert = ca_module.issue_authority_certificate(
            subject_common_name=f"AA-{ELECTION_ID}",
            subject_org_unit="Authentication Authority",
            public_key=aa_key.public_key(),
        )

        ca_cert = ca_module.load_ca_cert()
        if not ca_module.verify_certificate(aa_cert, ca_cert):
            raise RuntimeError("[AA] Verifica del certificato fallita.")

        with open(AA_KEY_FILE, "wb") as f:
            f.write(aa_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(AA_CERT_FILE, "wb") as f:
            f.write(aa_cert.public_bytes(serialization.Encoding.PEM))

        print(f"[AA] Setup completato.")
        print(f"     Chiave privata: {AA_KEY_FILE}")
        print(f"     Certificato:    {AA_CERT_FILE}")

        self._init_authorized_voters()

    def register_voter(self, voter_id: str, voter_pubkey_pem: bytes) -> bytes:
        """
        Registra un elettore e emette il certificato Cert_e.

        Flusso (Sezione 11 del protocollo):
          1. Verifica che voter_id sia nella lista degli aventi diritto
          2. Verifica anti-duplicato on-chain: registerVoter(H(ID_elettore))
          3. Emette Cert_e = Sign_skAA(pk_e || ID_elettore) come X.509
          4. Restituisce Cert_e in formato PEM

        Args:
            voter_id:         identificativo univoco dell'elettore
            voter_pubkey_pem: chiave pubblica pk_e dell'elettore in formato PEM

        Returns:
            Cert_e in formato PEM (bytes)

        Raises:
            ValueError: elettore non autorizzato o già registrato
        """
        print(f"\n[AA] === Registrazione elettore: {voter_id} ===")

        # Passo 1: verifica identità (fuori banda nella realtà)
        authorized = self._load_authorized_voters()
        if voter_id not in authorized:
            raise ValueError(
                f"[AA] RIFIUTATO: '{voter_id}' non presente nella lista degli aventi diritto."
            )
        print(f"[AA] Identità verificata: {authorized[voter_id]['nome']}")

        # Passo 2: registrazione anti-duplicato on-chain
        voter_id_hash = self._hash_voter_id(voter_id)
        print(f"[AA] H(ID_elettore): {voter_id_hash[:16]}...")
        blockchain.register_voter(voter_id_hash)

        # Passo 3: emissione Cert_e
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        voter_pubkey = load_pem_public_key(voter_pubkey_pem)
        aa_key  = self._load_key()
        aa_cert = self.load_cert()

        cert_e      = ca_module.issue_voter_certificate(
            voter_id=voter_id,
            voter_public_key=voter_pubkey,
            aa_key=aa_key,
            aa_cert=aa_cert,
        )
        cert_e_pem  = cert_e.public_bytes(serialization.Encoding.PEM)
        cert_e_hash = self._hash_cert(cert_e_pem)

        print(f"[AA] Cert_e emesso — H(Cert_e): {cert_e_hash[:16]}...")
        print(f"[AA] Registrazione completata per: {voter_id}")
        return cert_e_pem

    def verify_cert_e(self, cert_e_pem: bytes) -> bool:
        """
        Verifica che Cert_e sia stato emesso da AA.
        Usato da AR nella fase di autenticazione (Sezione 13).

        Returns:
            True se la firma AA sul certificato è valida
        """
        cert_e  = load_pem_x509_certificate(cert_e_pem)
        aa_cert = self.load_cert()
        return ca_module.verify_certificate(cert_e, aa_cert)

    def extract_voter_pubkey(self, cert_e_pem: bytes):
        """
        Estrae pk_e da Cert_e.

        Returns:
            Chiave pubblica RSA dell'elettore (pk_e)
        """
        return load_pem_x509_certificate(cert_e_pem).public_key()

    def load_cert(self):
        """Carica e restituisce il certificato AA come oggetto x509."""
        with open(AA_CERT_FILE, "rb") as f:
            return load_pem_x509_certificate(f.read())

    def load_cert_pem(self) -> bytes:
        """Restituisce il certificato AA in formato PEM (bytes)."""
        with open(AA_CERT_FILE, "rb") as f:
            return f.read()

    def _load_key(self) -> rsa.RSAPrivateKey:
        """Carica la chiave privata AA dal disco (uso interno)."""
        with open(AA_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _load_authorized_voters(self) -> dict:
        """
        Carica la lista degli aventi diritto al voto.
        Nella realtà gestita fuori banda; nella demo è un file JSON locale.
        """
        if not os.path.exists(AUTHORIZED_VOTERS_FILE):
            return {}
        with open(AUTHORIZED_VOTERS_FILE, "r") as f:
            return json.load(f)

    def _init_authorized_voters(self) -> None:
        """
        Crea il file degli elettori autorizzati di esempio se non esiste.
        Nella realtà questo registro proviene dal sistema elettorale istituzionale.
        """
        if os.path.exists(AUTHORIZED_VOTERS_FILE):
            return
        os.makedirs(PKI_DIR, exist_ok=True)
        voters = {
            "MarioRossi001":    {"nome": "Mario Rossi",    "codice_fiscale": "RSSMRA80A01H501U"},
            "LuigiVerdi002":    {"nome": "Luigi Verdi",    "codice_fiscale": "VRDLGU75B02F205X"},
            "AnnaBianchi003":   {"nome": "Anna Bianchi",   "codice_fiscale": "BNCNNA90C03G702K"},
            "CarloNeri004":     {"nome": "Carlo Neri",     "codice_fiscale": "NRECRL85D04L219P"},
            "GiuliaMarini005":  {"nome": "Giulia Marini",  "codice_fiscale": "MRNGLU92E05M082Q"},
        }
        with open(AUTHORIZED_VOTERS_FILE, "w") as f:
            json.dump(voters, f, indent=2, ensure_ascii=False)
        print(f"[AA] Lista elettori autorizzati creata: {AUTHORIZED_VOTERS_FILE}")
        print(f"     Elettori registrati: {list(voters.keys())}")

    @staticmethod
    def _hash_voter_id(voter_id: str) -> str:
        """
        Calcola H(ID_elettore) = SHA-256(voter_id UTF-8) per la registrazione on-chain.
        Garantisce che voter_id non venga mai trasmesso in chiaro alla blockchain.
        """
        return hashlib.sha256(voter_id.encode("utf-8")).hexdigest()

    @staticmethod
    def _hash_cert(cert_pem: bytes) -> str:
        """Calcola H(Cert_e) = SHA-256(PEM bytes), usato come chiave in issuedTokens."""
        return hashlib.sha256(cert_pem).hexdigest()


# ── Wrappers a livello modulo (compatibilità con gli altri moduli) ─────────────

def setup() -> None:
    """Delega a AuthenticationAuthority.setup()."""
    AuthenticationAuthority().setup()


def register_voter(voter_id: str, voter_pubkey_pem: bytes) -> bytes:
    """Delega a AuthenticationAuthority.register_voter()."""
    return AuthenticationAuthority().register_voter(voter_id, voter_pubkey_pem)


def verify_cert_e(cert_e_pem: bytes) -> bool:
    """Delega a AuthenticationAuthority.verify_cert_e()."""
    return AuthenticationAuthority().verify_cert_e(cert_e_pem)


def extract_voter_pubkey(cert_e_pem: bytes):
    """Delega a AuthenticationAuthority.extract_voter_pubkey()."""
    return AuthenticationAuthority().extract_voter_pubkey(cert_e_pem)


def load_aa_cert():
    """Delega a AuthenticationAuthority.load_cert()."""
    return AuthenticationAuthority().load_cert()


def load_aa_cert_pem() -> bytes:
    """Delega a AuthenticationAuthority.load_cert_pem()."""
    return AuthenticationAuthority().load_cert_pem()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    commands = {
        "setup":       "Inizializza l'AA",
        "register":    "Registra un elettore (voter_id)",
        "status":      "Mostra stato dell'AA",
        "list-voters": "Elenca gli elettori autorizzati",
    }
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print("Uso: python aa.py <comando> [argomenti]")
        print("\nComandi disponibili:")
        for cmd, desc in commands.items():
            print(f"  {cmd:<16} {desc}")
        sys.exit(1)

    cmd     = sys.argv[1]
    aa_auth = AuthenticationAuthority()

    if cmd == "setup":
        aa_auth.setup()

    elif cmd == "register":
        if len(sys.argv) < 3:
            print("Uso: python aa.py register <voter_id>")
            print("     La chiave pubblica deve essere in:")
            print(f"     {WALLETS_DIR}/<voter_id>/voter_key_pub.pem")
            sys.exit(1)
        voter_id    = sys.argv[2]
        pubkey_path = os.path.join(WALLETS_DIR, voter_id, "voter_key_pub.pem")
        if not os.path.exists(pubkey_path):
            print(f"[AA] Errore: chiave pubblica non trovata in {pubkey_path}")
            print(f"     L'elettore deve prima eseguire: python elettore.py keygen {voter_id}")
            sys.exit(1)
        with open(pubkey_path, "rb") as f:
            voter_pubkey_pem = f.read()
        cert_e_pem = aa_auth.register_voter(voter_id, voter_pubkey_pem)
        cert_path  = os.path.join(WALLETS_DIR, voter_id, "voter_cert.pem")
        with open(cert_path, "wb") as f:
            f.write(cert_e_pem)
        print(f"[AA] Cert_e salvato in: {cert_path}")

    elif cmd == "status":
        if not os.path.exists(AA_CERT_FILE):
            print("[AA] Non inizializzata. Esegui: python aa.py setup")
            sys.exit(1)
        cert   = aa_auth.load_cert()
        voters = aa_auth._load_authorized_voters()
        n_auth = sum(
            1 for vid in voters
            if blockchain.is_voter_registered(AuthenticationAuthority._hash_voter_id(vid))
        )
        print(f"[AA] Autorità di Autenticazione")
        print(f"     Subject:    {cert.subject.rfc4514_string()}")
        print(f"     Valido fino:{cert.not_valid_after_utc}")
        print(f"     Elettori registrati on-chain: {n_auth}")

    elif cmd == "list-voters":
        voters = aa_auth._load_authorized_voters()
        if not voters:
            print("[AA] Nessun elettore autorizzato trovato.")
        else:
            print("[AA] Elettori autorizzati:")
            for vid, info in voters.items():
                registered = blockchain.is_voter_registered(
                    AuthenticationAuthority._hash_voter_id(vid)
                )
                status = "✓ registrato" if registered else "○ non ancora registrato"
                print(f"     {vid:<20} {info['nome']:<20} {status}")
