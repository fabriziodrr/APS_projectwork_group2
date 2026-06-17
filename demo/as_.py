"""
as_.py — Autorità di Scrutinio (AS).

Responsabile di:
  - Setup chiavi di decifratura (sk_AS distribuita via Shamir) e firma (sk_AS_sign)
    — Sezione 10.4
  - Decifratura voti, calcolo risultato, Bulletin Board  — Sezione 16
  - Pubblicazione on-chain                               — Sezione 16.2

Schema Shamir (t=2, n=3):
  sk_AS NON è mai scritta su un singolo file; è suddivisa in 3 share
  custoditite dai garanti (share_1.json, share_2.json, share_3.json).
  Per lo scrutinio ne bastano t=2; la chiave viene ricostruita in memoria,
  usata per la decifratura e immediatamente distrutta.

Uso:
    python as_.py setup   — Inizializza AS (Shamir setup)
    python as_.py tally   — Esegue lo scrutinio
    python as_.py status  — Mostra stato
"""
import os
import sys
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

import blockchain
import ca as ca_module
import ec as ec_module
import shamir_setup
from crypto_utils import (
    sign, sha256_bytes, canonical_bytes, b64e, decrypt_vote,
    encrypt_share, decrypt_share, sign_share_packet, verify_share_packet,
    load_public_key_from_cert,
)
from config import (
    AS_CERT_FILE,
    AS_SIGN_KEY_FILE,
    AS_SIGN_CERT_FILE,
    AS_RECV_KEY_FILE,
    AS_RECV_CERT_FILE,
    PKI_DIR,
    BB_FILE,
    SHARE_1_PATH,
    SHARE_2_PATH,
    SHARE_3_PATH,
    GUARDIAN_1_KEY_FILE, GUARDIAN_2_KEY_FILE,
    GUARDIAN_1_CERT_FILE, GUARDIAN_2_CERT_FILE,
    SHARE_TS_WINDOW,
)


class ScrutinyAuthority:
    """
    Autorità di Scrutinio (AS) del sistema di voto APS.

    Gestisce il setup Shamir (delegato a ShamirScheme), la raccolta sicura
    delle share dai garanti (encrypt-then-sign), la ricostruzione in memoria
    di sk_AS, la decifratura dei voti, il calcolo del risultato, la costruzione
    del Bulletin Board e la pubblicazione on-chain.
    """

    def setup(self) -> None:
        """
        Fase di Setup AS — delega a ShamirScheme.setup() (Sezione 10.4):
          - Genera (pk_AS, sk_AS), applica Shamir (2,3), distrugge sk_AS
          - Distribuisce le 3 share ai garanti (share_1.json … share_3.json)
          - Genera separatamente (pk_AS_sign, sk_AS_sign) per la firma BB
        Dopo questa fase, sk_AS non esiste su disco.
        """
        shamir_setup.ShamirScheme().setup()

    def tally(self) -> dict:
        """
        Esegue lo scrutinio completo (Sezioni 16.1-16.2).

          1.  Verifica stato CLOSED on-chain
          2.  Recupera {C_voto_i} dalla blockchain
          3.  Verifica integrità urna (MerkleRootUrna)
          4a. Ricostruisce sk_AS tramite Shamir (t=2 share su 3) — Lagrange su GF(p)
          4b. Decifra ogni voto con sk_AS ricostruita
          4c. Distrugge sk_AS dalla memoria
          5.  Calcola R = Σ v_i
          6.  Costruisce Bulletin Board e MerkleRootBB
          7.  Firma BB con sk_AS_sign
          8.  Ottiene Att_risultato da EC
          9.  Pubblica on-chain → FINALIZED

        Returns:
            bulletin_board dict con risultato, Bulletin Board e attestazione EC
        """
        print(f"\n[AS] === Scrutinio ===")

        # 1. Stato CLOSED
        state = blockchain.get_state()
        if state != "CLOSED":
            raise PermissionError(f"[AS] Scrutinio non consentito: stato={state} (atteso: CLOSED)")
        print(f"[AS] Stato verificato: CLOSED")

        # 2. Recupera ancoraggi dalla blockchain
        anchors = blockchain.get_all_ballot_anchors()
        N = len(anchors)
        print(f"[AS] Schede recuperate: {N}")

        # 3. Verifica integrità urna
        info                   = blockchain.get_election_info()
        merkle_root_urna_chain = info["merkleRootUrna"]
        root_calcolata         = blockchain.compute_merkle_root_urna(anchors)

        if root_calcolata != merkle_root_urna_chain:
            raise ValueError(
                f"[AS] MerkleRootUrna non corrispondente:\n"
                f"     calcolata : {root_calcolata}\n"
                f"     on-chain  : {merkle_root_urna_chain}"
            )
        print(f"[AS] Integrità urna verificata — {root_calcolata[:20]}...")

        # 4a. Ricostruzione sk_AS tramite schema Shamir (t=2 su n=3)
        print(f"\n[AS-Shamir] === Ricostruzione sk_AS (Shamir t=2 su 3) ===")
        share_tuples, prime = self._collect_shares_secure()
        sk_as = shamir_setup.ShamirScheme().reconstruct_dec_key_from_data(share_tuples, prime)
        del share_tuples, prime

        # 4b. Decifratura voti con sk_AS ricostruita (RSA-OAEP — Sezione 14.2.1)
        votes      = []
        bb_entries = []

        for anchor in anchors:
            v      = decrypt_vote(bytes(anchor["cvoto"]), sk_as)
            commit = anchor["commitVoto"]
            seq    = anchor["seqNum"]
            votes.append(v)
            bb_entries.append({
                "seqNum":      seq,
                "v":           v,
                "commit_voto": commit,
                "ballot_hash": anchor["ballotHash"],
            })
            print(f"[AS]   [{seq}] v={v}  commit={commit[:16]}...")

        # 4c. Distrugge sk_AS dalla memoria
        del sk_as
        print(f"[AS-Shamir] sk_AS distrutta dalla memoria dopo la decifratura.")

        # 5. Risultato
        R = sum(votes)
        print(f"\n[AS] Risultato: R={R}  (Sì={R}, No={N-R}, Tot={N})")

        # 6. MerkleRootBB
        pairs          = [(e["v"], e["commit_voto"]) for e in bb_entries]
        merkle_root_bb = blockchain.compute_merkle_root_bb(pairs)
        print(f"[AS] MerkleRoot_BB: {merkle_root_bb[:20]}...")

        # 7. Firma BB con sk_AS_sign
        bb_payload = {
            "result":         R,
            "total_votes":    N,
            "merkle_root_bb": merkle_root_bb,
            "entries":        bb_entries,
        }
        sig_as = sign(self._load_sign_key(), sha256_bytes(canonical_bytes(bb_payload)))
        print(f"[AS] Bulletin Board firmato con sk_AS_sign.")

        # 8. Attestazione risultato da EC
        att_risultato = ec_module.attest_result(R, N, merkle_root_bb)

        # 9. Pubblica on-chain → FINALIZED
        blockchain.publish_result(R, N, merkle_root_bb, sig_as, att_risultato)

        # Salva Bulletin Board su disco
        bulletin_board = {
            **bb_payload,
            "sig_as_b64":       b64e(sig_as),
            "att_risultato":    att_risultato.decode(),
            "merkle_root_urna": merkle_root_urna_chain,
        }
        os.makedirs(PKI_DIR, exist_ok=True)
        with open(BB_FILE, "w") as f:
            json.dump(bulletin_board, f, indent=2)
        print(f"[AS] Bulletin Board salvato: {BB_FILE}")

        return bulletin_board

    def load_cert_pem(self) -> bytes:
        """Restituisce il certificato pk_AS in formato PEM (bytes)."""
        with open(AS_CERT_FILE, "rb") as f:
            return f.read()

    def load_sign_cert_pem(self) -> bytes:
        """Restituisce il certificato pk_AS_sign in formato PEM (bytes)."""
        with open(AS_SIGN_CERT_FILE, "rb") as f:
            return f.read()

    def load_pubkey(self):
        """Restituisce pk_AS — chiave pubblica di cifratura voti (dal certificato)."""
        return load_pem_x509_certificate(self.load_cert_pem()).public_key()

    def load_sign_pubkey(self):
        """Restituisce pk_AS_sign — chiave pubblica di verifica firma BB (dal certificato)."""
        return load_pem_x509_certificate(self.load_sign_cert_pem()).public_key()

    def _load_sign_key(self):
        """Carica sk_AS_sign (chiave di firma BB — mai distribuita, sempre disponibile)."""
        with open(AS_SIGN_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _collect_shares_secure(self) -> tuple:
        """
        Raccoglie 2 share su 3 dai garanti simulati in-process usando encrypt-then-sign.
        Ogni garante cifra la propria share con pk_AS_recv e la firma con sk_Gj.
        AS verifica firma, decifra, controlla nonce e timestamp prima di accettare.

        Returns:
            (share_tuples: list[(gid, value)], prime: int)
        """
        with open(AS_RECV_KEY_FILE, "rb") as f:
            sk_as_recv = serialization.load_pem_private_key(f.read(), password=None)
        pk_as_recv = load_pem_x509_certificate(
            open(AS_RECV_CERT_FILE, "rb").read()
        ).public_key()

        ca_cert = ca_module.load_ca_cert()

        guardian_key_files  = [GUARDIAN_1_KEY_FILE,  GUARDIAN_2_KEY_FILE]
        guardian_cert_files = [GUARDIAN_1_CERT_FILE, GUARDIAN_2_CERT_FILE]
        share_paths         = [SHARE_1_PATH,          SHARE_2_PATH]

        share_tuples = []
        prime        = None
        used_nonces  = set()

        for kf, cf, sp in zip(guardian_key_files, guardian_cert_files, share_paths):
            with open(sp) as f:
                raw = json.load(f)
            share_val = int(raw["share"])
            gid       = int(raw["garante_id"])
            p_val     = int(raw["prime"])
            if prime is None:
                prime = p_val

            # Lato garante (simulato): cifratura + firma
            with open(kf, "rb") as f:
                sk_g = serialization.load_pem_private_key(f.read(), password=None)
            packet = encrypt_share(share_val, gid, pk_as_recv)
            sig    = sign_share_packet(packet, sk_g)

            # Lato AS: verifica certificato garante
            cert_g_pem = open(cf, "rb").read()
            cert_g     = load_pem_x509_certificate(cert_g_pem)
            if not ca_module.verify_certificate(cert_g, ca_cert):
                raise ValueError(f"[AS] Cert garante_{gid} non autentico.")

            # Lato AS: verifica firma sul pacchetto
            pk_g = cert_g.public_key()
            if not verify_share_packet(packet, sig, pk_g):
                raise ValueError(f"[AS] Firma pacchetto garante_{gid} non valida.")

            # Lato AS: decifratura e controlli anti-replay / freschezza
            s_j, id_j, nonce_j, ts_j = decrypt_share(packet, sk_as_recv)
            if id_j != gid:
                raise ValueError(f"[AS] guardian_id mismatch: atteso {gid}, ricevuto {id_j}.")
            nonce_hex = nonce_j.hex()
            if nonce_hex in used_nonces:
                raise ValueError(f"[AS] Nonce duplicato dal garante_{gid}.")
            if abs(ts_j - time.time()) > SHARE_TS_WINDOW:
                raise ValueError(f"[AS] Timestamp pacchetto garante_{gid} fuori finestra.")
            used_nonces.add(nonce_hex)

            share_tuples.append((gid, s_j))
            print(f"[AS] Share garante_{gid} ricevuta, verificata e decifrata.")

        return share_tuples, prime


# ── Wrappers a livello modulo (compatibilità con gui.py, start_all.py, ecc.) ──

def setup() -> None:
    """Delega a ScrutinyAuthority.setup()."""
    ScrutinyAuthority().setup()


def tally() -> dict:
    """Delega a ScrutinyAuthority.tally()."""
    return ScrutinyAuthority().tally()


def load_as_cert_pem() -> bytes:
    """Delega a ScrutinyAuthority.load_cert_pem()."""
    return ScrutinyAuthority().load_cert_pem()


def load_as_sign_cert_pem() -> bytes:
    """Delega a ScrutinyAuthority.load_sign_cert_pem()."""
    return ScrutinyAuthority().load_sign_cert_pem()


def load_as_pubkey():
    """Delega a ScrutinyAuthority.load_pubkey()."""
    return ScrutinyAuthority().load_pubkey()


def load_as_sign_pubkey():
    """Delega a ScrutinyAuthority.load_sign_pubkey()."""
    return ScrutinyAuthority().load_sign_pubkey()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cmds = {"setup": "Inizializza AS (Shamir)", "tally": "Esegui scrutinio", "status": "Stato AS"}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print("Uso: python as_.py <setup|tally|status>")
        sys.exit(1)

    as_auth = ScrutinyAuthority()
    cmd     = sys.argv[1]

    if cmd == "setup":
        as_auth.setup()
    elif cmd == "tally":
        bb = as_auth.tally()
        print(f"\n{'='*50}")
        print(f"  RISULTATO: Sì={bb['result']}  No={bb['total_votes']-bb['result']}  Tot={bb['total_votes']}")
    elif cmd == "status":
        print(f"[AS] Stato contratto: {blockchain.get_state()}")
        shares_ok = all(os.path.exists(p) for p in [SHARE_1_PATH, SHARE_2_PATH, SHARE_3_PATH])
        print(f"[AS] Share Shamir (3/3): {'presenti' if shares_ok else 'mancanti'}")
        if os.path.exists(BB_FILE):
            with open(BB_FILE) as f:
                bb = json.load(f)
            print(f"[AS] BB pubblicato: R={bb['result']}/{bb['total_votes']}")
        else:
            print(f"[AS] BB non ancora pubblicato.")
