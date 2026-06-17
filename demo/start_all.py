#!/usr/bin/env python3
"""
start_all.py — Demo completa del flusso di votazione APS.

Esegue in sequenza tutte le fasi del protocollo WP2:
  Setup → Registrazione → Apertura → Autenticazione → Voto →
  Chiusura → Scrutinio → Verifica

Uso:
    python start_all.py            — Esegue la demo completa
    python start_all.py --clean    — Rimuove stato precedente e riesegue
"""
import os, sys, shutil, time

SEP  = "=" * 62
SEP2 = "─" * 50

def clean():
    for d in ["aps-voting-pki", "contracts_out"]:
        if os.path.exists(d):
            shutil.rmtree(d)
    print("[Demo] Stato precedente rimosso.\n")

def header(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)

def step(n, title):
    print(f"\n{SEP2}")
    print(f"  [Step {n}] {title}")
    print(SEP2)

def run():
    # Import ritardato per permettere --clean prima del setup
    import blockchain, ca, aa, ar, as_, ec
    import elettore, verifica

    VOTERS = [
        ("MarioRossi001",   1),   # vota Sì
        ("LuigiVerdi002",   0),   # vota No
        ("AnnaBianchi003",  1),   # vota Sì
        ("CarloNeri004",    1),   # vota Sì
        ("GiuliaMarini005", 0),   # vota No
    ]
    # Risultato atteso: Sì=3, No=2

    header("APS Voting System — Demo Completa WP2")

    # ══ SETUP ════════════════════════════════════════════════════════════════

    step(1, "Deploy VotingContract su Ganache")
    blockchain.deploy_contract()

    step(2, "Inizializzazione Certification Authority (CA)")
    ca.setup()

    step(3, "Inizializzazione autorità: AA, AR, AS, EC")
    aa.setup()
    ar.setup()
    as_.setup()
    ec.setup()

    # ══ REGISTRAZIONE ════════════════════════════════════════════════════════

    step(4, f"Registrazione {len(VOTERS)} elettori presso AA")
    for voter_id, _ in VOTERS:
        elettore.keygen(voter_id)
        elettore.register(voter_id)

    # ══ APERTURA URNE ════════════════════════════════════════════════════════

    step(5, "Apertura urne — EC emette Att_apertura e transita a OPEN")
    ec.attest_open()
    print(f"[Demo] Stato contratto: {blockchain.get_state()}")

    # ══ AUTENTICAZIONE + VOTO ════════════════════════════════════════════════

    step(6, "Autenticazione e voto")
    for voter_id, choice in VOTERS:
        print(f"\n  {'─'*45}")
        print(f"  Elettore: {voter_id}  →  {'Sì' if choice else 'No'}")
        elettore.auth(voter_id)
        elettore.vote(voter_id, choice)

    # Riepilogo stato on-chain dopo il voto
    print(f"\n[Demo] Schede ancorate on-chain: {blockchain.get_ballot_count()}")

    # ══ CHIUSURA URNE ════════════════════════════════════════════════════════

    step(7, "Chiusura urne — EC emette Att_chiusura e transita a CLOSED")
    att_chiusura, merkle_root_urna = ec.attest_close()
    print(f"[Demo] Stato contratto: {blockchain.get_state()}")
    print(f"[Demo] MerkleRootUrna: {merkle_root_urna[:24]}...")

    # ══ SCRUTINIO ════════════════════════════════════════════════════════════

    step(8, "Scrutinio — AS decifra, calcola risultato, pubblica BB")
    bb = as_.tally()
    print(f"\n  RISULTATO UFFICIALE:")
    print(f"  Sì  = {bb['result']}")
    print(f"  No  = {bb['total_votes'] - bb['result']}")
    print(f"  Tot = {bb['total_votes']}")
    print(f"[Demo] Stato contratto: {blockchain.get_state()}")

    # ══ VERIFICA ═════════════════════════════════════════════════════════════

    step(9, "Verifica individuale per ogni elettore")
    for voter_id, _ in VOTERS:
        verifica.verify_individual(voter_id)

    step(10, "Verifica universale (chiunque, senza credenziali)")
    verifica.verify_universal()

    # ══ RIEPILOGO FINALE ═════════════════════════════════════════════════════

    header("Riepilogo finale")
    info = blockchain.get_election_info()
    print(f"  Stato contratto:     {info['state']}")
    print(f"  Schede ancorate:     {info['ballotCount']}")
    print(f"  Risultato on-chain:  R={info['finalResult']}/{info['totalVotes']}")
    print(f"  MerkleRootUrna:      {info['merkleRootUrna'][:24]}...")
    print(f"  MerkleRootBB:        {info['merkleRootBB'][:24]}...")
    print(f"\n[Demo] Completata con successo.\n")


if __name__ == "__main__":
    if "--clean" in sys.argv:
        clean()
    run()
