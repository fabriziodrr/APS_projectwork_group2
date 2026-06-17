"""
config.py — Configurazione condivisa del sistema di voto APS.
"""
import os

# ── Directory structure ───────────────────────────────────────────────────────
PKI_DIR      = "aps-voting-pki"
CA_DIR       = os.path.join(PKI_DIR, "ca")
AA_DIR       = os.path.join(PKI_DIR, "authorities", "aa")
AR_DIR       = os.path.join(PKI_DIR, "authorities", "ar")
AS_DIR       = os.path.join(PKI_DIR, "authorities", "as")
EC_DIR       = os.path.join(PKI_DIR, "authorities", "ec")
WALLETS_DIR  = os.path.join(PKI_DIR, "wallets")
BB_FILE      = os.path.join(PKI_DIR, "bulletin_board.json")

CA_KEY_FILE  = os.path.join(CA_DIR, "ca_key.pem")
CA_CERT_FILE = os.path.join(CA_DIR, "ca_cert.pem")
AA_KEY_FILE  = os.path.join(AA_DIR, "aa_key.pem")
AA_CERT_FILE = os.path.join(AA_DIR, "aa_cert.pem")
AR_KEY_FILE  = os.path.join(AR_DIR, "ar_key.pem")
AR_CERT_FILE = os.path.join(AR_DIR, "ar_cert.pem")
AS_KEY_FILE  = os.path.join(AS_DIR, "as_key.pem")         # chiave di decifratura (non usata con Shamir)
AS_SIGN_KEY_FILE  = os.path.join(AS_DIR, "as_sign_key.pem")  # chiave di firma BB (mai distribuita)
AS_CERT_FILE = os.path.join(AS_DIR, "as_cert.pem")
AS_SIGN_CERT_FILE = os.path.join(AS_DIR, "as_sign_cert.pem")
AS_RECV_KEY_FILE  = os.path.join(AS_DIR, "as_recv_key.pem")  # chiave ricezione share cifrate
AS_RECV_CERT_FILE = os.path.join(AS_DIR, "as_recv_cert.pem")

GUARDIAN_1_KEY_FILE  = os.path.join(AS_DIR, "guardian_1_key.pem")
GUARDIAN_2_KEY_FILE  = os.path.join(AS_DIR, "guardian_2_key.pem")
GUARDIAN_3_KEY_FILE  = os.path.join(AS_DIR, "guardian_3_key.pem")
GUARDIAN_1_CERT_FILE = os.path.join(AS_DIR, "guardian_1_cert.pem")
GUARDIAN_2_CERT_FILE = os.path.join(AS_DIR, "guardian_2_cert.pem")
GUARDIAN_3_CERT_FILE = os.path.join(AS_DIR, "guardian_3_cert.pem")

# ── Shamir (t=2, n=3) share paths ─────────────────────────────────────────────
# Ogni garante custodisce il proprio file; per lo scrutinio bastano t=2 share.
SHARE_1_PATH = os.path.join(AS_DIR, "share_1.json")
SHARE_2_PATH = os.path.join(AS_DIR, "share_2.json")
SHARE_3_PATH = os.path.join(AS_DIR, "share_3.json")
EC_KEY_FILE  = os.path.join(EC_DIR, "ec_key.pem")
EC_CERT_FILE = os.path.join(EC_DIR, "ec_cert.pem")

AUTHORIZED_VOTERS_FILE = os.path.join(PKI_DIR, "authorized_voters.json")
CONTRACT_INFO_FILE     = os.path.join(PKI_DIR, "contract_info.json")

# ── Parametri crittografici ───────────────────────────────────────────────────
RSA_KEY_SIZE   = 2048
NONCE_SIZE     = 16    # byte (128 bit)
RCOMMIT_SIZE   = 32    # byte (256 bit)
RVOTO_SIZE     = 16    # byte (128 bit)
REPLAY_WINDOW  = 300   # secondi (5 min)
TOKEN_LIFETIME = 3600  # secondi (1 ora)
SHARE_NONCE_SIZE       = 16         # byte — nonce anti-replay nei pacchetti share
SHARE_TS_WINDOW        = 300        # secondi — finestra temporale validità pacchetto share
SCRUTINY_DEADLINE_DELTA = 7 * 24 * 3600  # secondi — deadline scrutinio (7 giorni)

# ── Certificati ───────────────────────────────────────────────────────────────
CA_CERT_DAYS    = 3650
AUTH_CERT_DAYS  = 365
VOTER_CERT_DAYS = 30

# ── Elezione ──────────────────────────────────────────────────────────────────
ELECTION_ID = "REFERENDUM-2026-APS"

# ── Ganache (rete locale deterministica) ─────────────────────────────────────
GANACHE_URL = "http://127.0.0.1:7545"
CHAIN_ID    = 1337

# Account Ethereum (ganache --deterministic)
# Assegnazione ruoli:  0=deployer  1=AA  2=AR  3=AS  4=EC
ETH_ACCOUNTS = {
    "deployer": {
        "address":     "0x51D63eb55802664fC1F6FB80e722E81e9E232C16",
        "private_key": "0x4d0db9cfe9e767c574db1b949b275b35ce52742e4ddee51e060477bfef93fc5b",
    },
    "AA": {
        "address":     "0xA4fEf704f237e9fC81a5B883FfC5498971126886",
        "private_key": "0x3c281b6a93757d881dc57a6f6bec100f69b547e8ca6291331ffe6ba7bbfd5811",
    },
    "AR": {
        "address":     "0xFE4E472A68d5da5e3c8c90924CC7ca48796aEDF7",
        "private_key": "0xaff7136499fb2632cfd629292ea3f4a664b0e3bd74f9487a321cf9bdcf8bf253",
    },
    "AS": {
        "address":     "0x510a08be25A667EE264180d6Ef58236F68459Bc6",
        "private_key": "0x74cbf9074b42f8c8c69fb7b7de958ce0de64bbf27c0048f05590d9c7a46d28b7",
    },
    "EC": {
        "address":     "0x475dB0C0d80B33cC7C74E4867CdEb5a9491b0931",
        "private_key": "0xc60ee6e7928b3f1e297e2eac4708cf8f048fc9470091174b7356818563993e98",
    },
}

# Percorso contratto Solidity e output compilazione
SOL_FILE       = os.path.join("contracts", "VotingContract.sol")
SOL_OUTPUT_DIR = "contracts_out"
ABI_FILE       = os.path.join(SOL_OUTPUT_DIR, "VotingContract.abi")
BIN_FILE       = os.path.join(SOL_OUTPUT_DIR, "VotingContract.bin")