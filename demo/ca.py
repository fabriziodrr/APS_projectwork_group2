"""
ca.py — Certification Authority del sistema di voto.

Costituisce il trust anchor della PKI. Genera il certificato radice
self-signed e firma i certificati delle autorità (AA, AR, AS, EC) e
degli elettori previa verifica dell'identità.

Uso:
    python ca.py setup       — Inizializza CA (genera chiavi e cert radice)
    python ca.py status      — Mostra informazioni sul certificato radice
"""

import os
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from config import (
    CA_DIR, CA_KEY_FILE, CA_CERT_FILE,
    RSA_KEY_SIZE, CA_CERT_DAYS, AUTH_CERT_DAYS, VOTER_CERT_DAYS,
    ELECTION_ID,
)


class CertificationAuthority:
    """
    Autorità di Certificazione radice (Root CA) del sistema di voto APS.

    Costituisce il trust anchor dell'intera PKI: emette certificati X.509
    per le autorità (AA, AR, AS, EC) e, tramite AA, per gli elettori.
    Non partecipa alle fasi di voto né di scrutinio.
    """

    def setup(self) -> None:
        """
        Inizializza la CA:
          1. Genera coppia di chiavi RSA (sk_CA, pk_CA)
          2. Emette certificato radice self-signed
          3. Salva chiave privata e certificato su disco
        """
        if os.path.exists(CA_KEY_FILE):
            print("[CA] Setup già eseguito. Usa 'status' per verificare.")
            return

        os.makedirs(CA_DIR, exist_ok=True)

        print("[CA] Generazione coppia di chiavi RSA...")
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend(),
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,             "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "APS Voting System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME,              f"CA-{ELECTION_ID}"),
        ])

        now  = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=CA_CERT_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        with open(CA_KEY_FILE, "wb") as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(CA_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"[CA] Setup completato.")
        print(f"     Chiave privata: {CA_KEY_FILE}")
        print(f"     Certificato:    {CA_CERT_FILE}")
        print(f"     Valido fino a:  {cert.not_valid_after_utc}")

    def issue_authority_certificate(
        self,
        subject_common_name: str,
        subject_org_unit: str,
        public_key: rsa.RSAPublicKey,
    ) -> x509.Certificate:
        """
        Emette un certificato X.509 per un'autorità del sistema (AA, AR, AS, EC).
        Richiede autenticazione istituzionale fuori banda (già avvenuta).

        Args:
            subject_common_name: CN dell'autorità (es. "AA-REFERENDUM-2026")
            subject_org_unit:    OU dell'autorità (es. "Authentication Authority")
            public_key:          chiave pubblica RSA dell'autorità richiedente

        Returns:
            Certificato X.509 firmato dalla CA
        """
        ca_key  = self._load_key()
        ca_cert = self.load_cert()
        now     = datetime.datetime.utcnow()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,             "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "APS Voting System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_org_unit),
            x509.NameAttribute(NameOID.COMMON_NAME,              subject_common_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=AUTH_CERT_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_cert_sign=False, crl_sign=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        print(f"[CA] Certificato emesso per: {subject_common_name}")
        return cert

    def issue_voter_certificate(
        self,
        voter_id: str,
        voter_public_key: rsa.RSAPublicKey,
        aa_key: rsa.RSAPrivateKey,
        aa_cert: x509.Certificate,
    ) -> x509.Certificate:
        """
        Emette il certificato elettore Cert_e = Sign_skAA(pk_e || ID_elettore).
        Firmato da AA (non dalla CA) per separare le responsabilità nel protocollo.

        Il campo SubjectAlternativeName trasporta voter_id in modo standard.
        La chiave pubblica pk_e è incorporata nel certificato X.509.

        Args:
            voter_id:         identificativo univoco dell'elettore
            voter_public_key: pk_e generata localmente dall'elettore
            aa_key:           chiave privata dell'AA (sk_AA)
            aa_cert:          certificato dell'AA (per il campo issuer)

        Returns:
            Certificato X.509 dell'elettore (Cert_e), firmato da AA
        """
        now     = datetime.datetime.utcnow()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,             "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "APS Voting System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Voter"),
            x509.NameAttribute(NameOID.COMMON_NAME,              voter_id),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(aa_cert.subject)
            .public_key(voter_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=VOTER_CERT_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_cert_sign=False, crl_sign=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            # SAN: trasporta voter_id come RFC822Name (non esposto fuori da AA)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.RFC822Name(f"{voter_id}@aps-voting.local")
                ]),
                critical=False,
            )
            .sign(aa_key, hashes.SHA256(), default_backend())
        )
        return cert

    def verify_certificate(
        self,
        cert: x509.Certificate,
        issuer_cert: x509.Certificate,
    ) -> bool:
        """
        Verifica che cert sia stato firmato da issuer_cert.

        Returns:
            True se la firma è valida, False altrimenti
        """
        try:
            issuer_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False

    def load_cert(self) -> x509.Certificate:
        """Carica e restituisce il certificato radice CA come oggetto x509."""
        with open(CA_CERT_FILE, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def load_cert_pem(self) -> bytes:
        """Restituisce il certificato radice CA in formato PEM (bytes)."""
        with open(CA_CERT_FILE, "rb") as f:
            return f.read()

    def _load_key(self) -> rsa.RSAPrivateKey:
        """Carica la chiave privata CA dal disco (uso interno)."""
        with open(CA_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)


# ── Wrappers a livello modulo (compatibilità con gli altri moduli) ─────────────

def setup() -> None:
    """Delega a CertificationAuthority.setup()."""
    CertificationAuthority().setup()


def load_ca_cert() -> x509.Certificate:
    """Delega a CertificationAuthority.load_cert()."""
    return CertificationAuthority().load_cert()


def load_ca_cert_pem() -> bytes:
    """Delega a CertificationAuthority.load_cert_pem()."""
    return CertificationAuthority().load_cert_pem()


def issue_authority_certificate(
    subject_common_name: str,
    subject_org_unit: str,
    public_key: rsa.RSAPublicKey,
) -> x509.Certificate:
    """Delega a CertificationAuthority.issue_authority_certificate()."""
    return CertificationAuthority().issue_authority_certificate(
        subject_common_name, subject_org_unit, public_key
    )


def issue_voter_certificate(
    voter_id: str,
    voter_public_key: rsa.RSAPublicKey,
    aa_key: rsa.RSAPrivateKey,
    aa_cert: x509.Certificate,
) -> x509.Certificate:
    """Delega a CertificationAuthority.issue_voter_certificate()."""
    return CertificationAuthority().issue_voter_certificate(
        voter_id, voter_public_key, aa_key, aa_cert
    )


def verify_certificate(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Delega a CertificationAuthority.verify_certificate()."""
    return CertificationAuthority().verify_certificate(cert, issuer_cert)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    commands = {
        "setup":  "Inizializza la CA (genera chiavi e certificato radice)",
        "status": "Mostra informazioni sul certificato radice",
    }
    if len(sys.argv) < 2 or sys.argv[1] not in commands:
        print("Uso: python ca.py <comando>")
        print("\nComandi disponibili:")
        for cmd, desc in commands.items():
            print(f"  {cmd:<10} {desc}")
        sys.exit(1)

    cmd = sys.argv[1]
    ca  = CertificationAuthority()

    if cmd == "setup":
        ca.setup()
    elif cmd == "status":
        if not os.path.exists(CA_CERT_FILE):
            print("[CA] Non inizializzata. Esegui: python ca.py setup")
            sys.exit(1)
        cert = ca.load_cert()
        print(f"[CA] Certificato radice")
        print(f"     Subject:    {cert.subject.rfc4514_string()}")
        print(f"     Serial:     {cert.serial_number}")
        print(f"     Valido da:  {cert.not_valid_before_utc}")
        print(f"     Valido fino:{cert.not_valid_after_utc}")
