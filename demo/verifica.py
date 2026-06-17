"""
verifica.py — Meccanismi di verifica (Sezione 17).

Verifica individuale (Sezione 17.1) — 3 controlli:
  1. Scheda ancorata on-chain?       (Commit_voto on-chain == locale)
  2. Receipt firmata correttamente?  (firma AR su H(B)||seqNum||ts)
  3. Voto conteggiato correttamente? (apertura commitment nel BB)

Verifica universale (Sezione 17.2) — 4 controlli:
  1. Coerenza commitment AR ↔ AS    (commit on-chain == commit nel BB)
  2. Correttezza conteggio           (R == Σ v_i)
  3. Integrità BB                    (firma σ_AS_sign)
  4. Attestazione legale EC          (firma EC sul risultato)

Uso:
    python verifica.py individuale <voter_id>
    python verifica.py universale
"""
import os, sys, json
from config import WALLETS_DIR, BB_FILE
from crypto_utils import (
    verify_commit, verify_receipt, verify_sig,
    sha256_bytes, canonical_bytes, b64d,
)


class Verifier:
    """
    Classe di verifica del sistema di voto APS.

    Implementa i meccanismi di verifica descritti nella Sezione 17:
    verifica individuale (3 controlli per singolo elettore) e verifica
    universale (4 controlli globali sul Bulletin Board e sulla blockchain).
    Non richiede credenziali private: tutti i dati usati sono pubblici o locali.
    """

    def verify_individual(self, voter_id: str) -> bool:
        """
        Esegue i tre controlli di verifica individuale per voter_id (Sezione 17.1).

          1. Scheda ancorata on-chain: commit_voto on-chain == locale
          2. Receipt firmata da AR: verifica firma AR su (H(B)||seqNum||ts)
          3. Voto conteggiato nel BB: apertura commitment (v, r_commit) == BB.v

        Args:
            voter_id: identificativo dell'elettore da verificare

        Returns:
            True solo se tutti i controlli disponibili passano
        """
        print(f"\n[Verifica] === Individuale: {voter_id} ===")

        ballot_path = os.path.join(WALLETS_DIR, voter_id, "ballot.json")
        if not os.path.exists(ballot_path):
            print(f"[Verifica] Dati locali non trovati — il voto non è ancora stato espresso.")
            return False

        with open(ballot_path) as f:
            local = json.load(f)

        v           = local["v"]
        r_commit    = bytes.fromhex(local["r_commit"])
        seq_num     = local["seq_num"]
        ballot      = local["ballot"]
        receipt     = local["receipt"]
        commit_voto = ballot["commit_voto"]

        import blockchain, ar as ar_module

        ok1 = ok2 = ok3 = False

        # ── Controllo 1: scheda ancorata on-chain ─────────────────────────────
        try:
            anchor = blockchain.get_ballot_anchor(seq_num)
            ok1    = (anchor["commitVoto"] == commit_voto)
            sym    = "✓" if ok1 else "✗"
            print(f"[Verifica] [{sym}] Controllo 1 — Scheda ancorata on-chain")
            if not ok1:
                print(f"           atteso  : {commit_voto[:24]}...")
                print(f"           on-chain: {anchor['commitVoto'][:24]}...")
        except Exception as e:
            print(f"[Verifica] [✗] Controllo 1 — Errore: {e}")

        # ── Controllo 2: receipt firmata da AR ────────────────────────────────
        try:
            pk_ar = ar_module.load_ar_pubkey()
            ok2   = verify_receipt(receipt, pk_ar)
            sym   = "✓" if ok2 else "✗"
            print(f"[Verifica] [{sym}] Controllo 2 — Receipt AR autentica")
            if ok2:
                rp = receipt["payload"]
                print(f"           seqNum={rp['seq_num']}, H(B)={rp['ballot_hash'][:20]}...")
        except Exception as e:
            print(f"[Verifica] [✗] Controllo 2 — Errore: {e}")

        # ── Controllo 3: voto conteggiato correttamente nel BB ────────────────
        if not os.path.exists(BB_FILE):
            print(f"[Verifica] [?] Controllo 3 — BB non ancora pubblicato (scrutinio in attesa)")
            all_ok = ok1 and ok2
        else:
            try:
                with open(BB_FILE) as f:
                    bb = json.load(f)
                commit_ok = verify_commit(v, r_commit, commit_voto)
                bb_entry  = next((e for e in bb["entries"] if e["seqNum"] == seq_num), None)
                if bb_entry is None:
                    print(f"[Verifica] [✗] Controllo 3 — seqNum={seq_num} non trovato nel BB")
                else:
                    v_bb = bb_entry["v"]
                    ok3  = commit_ok and (v_bb == v)
                    sym  = "✓" if ok3 else "✗"
                    print(f"[Verifica] [{sym}] Controllo 3 — Voto conteggiato correttamente")
                    if ok3:
                        print(f"           v={v} ({'Sì' if v else 'No'}), "
                              f"binding OK, BB.v={v_bb}")
                    else:
                        print(f"           commit_ok={commit_ok}, v_locale={v}, v_BB={v_bb}")
            except Exception as e:
                print(f"[Verifica] [✗] Controllo 3 — Errore: {e}")
            all_ok = ok1 and ok2 and ok3

        sym = "✓ PASS" if all_ok else "✗ FAIL"
        print(f"[Verifica] Individuale {voter_id}: {sym}\n")
        return all_ok

    def verify_universal(self) -> bool:
        """
        Esegue i quattro controlli di verifica universale (Sezione 17.2).
        Non richiede credenziali: tutti i dati sono on-chain o nel BB pubblico.

          1. Coerenza commit AR ↔ AS: ogni commit on-chain coincide col BB
          2. Correttezza conteggio: R == Σ v_i == blockchain.finalResult
          3. Integrità BB: verifica firma σ_AS_sign su bb_payload
          4. Attestazione EC: verifica firma EC sull'attestazione risultato

        Returns:
            True solo se tutti i quattro controlli passano
        """
        print(f"\n[Verifica] === Universale ===")

        if not os.path.exists(BB_FILE):
            print("[Verifica] Bulletin Board non ancora pubblicato.")
            return False

        with open(BB_FILE) as f:
            bb = json.load(f)

        import blockchain, as_ as as_module, ec as ec_module

        ok1 = ok2 = ok3 = ok4 = False

        # ── Controllo 1: Coerenza commitment AR ↔ AS ─────────────────────────
        try:
            anchors    = blockchain.get_all_ballot_anchors()
            entries    = bb["entries"]
            n_chain    = len(anchors)
            n_bb       = len(entries)
            mismatches = 0
            for anchor in anchors:
                seq   = anchor["seqNum"]
                entry = next((e for e in entries if e["seqNum"] == seq), None)
                if entry is None or anchor["commitVoto"] != entry["commit_voto"]:
                    mismatches += 1
                    print(f"[Verifica]   mismatch commit seqNum={seq}")
            ok1 = (mismatches == 0 and n_chain == n_bb)
            sym = "✓" if ok1 else "✗"
            print(f"[Verifica] [{sym}] Controllo 1 — Coerenza AR↔AS "
                  f"({n_chain} schede, {mismatches} mismatch)")
        except Exception as e:
            print(f"[Verifica] [✗] Controllo 1 — Errore: {e}")

        # ── Controllo 2: Correttezza conteggio ────────────────────────────────
        try:
            R_calc  = sum(e["v"] for e in bb["entries"])
            R_bb    = bb["result"]
            R_chain = blockchain.get_election_info()["finalResult"]
            ok2     = (R_calc == R_bb == R_chain)
            sym     = "✓" if ok2 else "✗"
            print(f"[Verifica] [{sym}] Controllo 2 — Conteggio: "
                  f"Σv_i={R_calc}, BB.R={R_bb}, Chain.R={R_chain}")
        except Exception as e:
            print(f"[Verifica] [✗] Controllo 2 — Errore: {e}")

        # ── Controllo 3: Integrità BB (firma σ_AS_sign) ───────────────────────
        try:
            pk_as_sign = as_module.load_as_sign_pubkey()
            sig_as     = b64d(bb["sig_as_b64"])
            bb_payload = {
                "result":         bb["result"],
                "total_votes":    bb["total_votes"],
                "merkle_root_bb": bb["merkle_root_bb"],
                "entries":        bb["entries"],
            }
            ok3 = verify_sig(
                pk_as_sign,
                sha256_bytes(canonical_bytes(bb_payload)),
                sig_as
            )
            sym = "✓" if ok3 else "✗"
            print(f"[Verifica] [{sym}] Controllo 3 — Firma σ_AS_sign sul BB valida")
        except Exception as e:
            print(f"[Verifica] [✗] Controllo 3 — Errore: {e}")

        # ── Controllo 4: Attestazione legale EC ───────────────────────────────
        try:
            att_json = bb["att_risultato"].encode()
            ok4      = ec_module.verify_att(att_json, "RISULTATO")
            sym      = "✓" if ok4 else "✗"
            print(f"[Verifica] [{sym}] Controllo 4 — Attestazione EC valida")
        except Exception as e:
            print(f"[Verifica] [✗] Controllo 4 — Errore: {e}")

        # ── MerkleRootBB ricalcolata ──────────────────────────────────────────
        try:
            pairs   = [(e["v"], e["commit_voto"]) for e in bb["entries"]]
            mr_calc = blockchain.compute_merkle_root_bb(pairs)
            mr_bb   = bb["merkle_root_bb"]
            mr_ok   = (mr_calc == mr_bb)
            sym     = "✓" if mr_ok else "✗"
            print(f"[Verifica] [{sym}] MerkleRootBB ricalcolata: {mr_calc[:20]}...")
        except Exception as e:
            print(f"[Verifica] [?] MerkleRootBB — {e}")

        all_ok = ok1 and ok2 and ok3 and ok4
        sym    = "✓ PASS" if all_ok else "✗ FAIL"
        print(f"\n[Verifica] Universale: {sym}")
        if all_ok:
            print(f"           Sì={bb['result']}  "
                  f"No={bb['total_votes']-bb['result']}  "
                  f"Tot={bb['total_votes']}")
        return all_ok


# ── Wrappers a livello modulo (compatibilità con gui.py, start_all.py) ────────

def verify_individual(voter_id: str) -> bool:
    """Delega a Verifier.verify_individual()."""
    return Verifier().verify_individual(voter_id)


def verify_universal() -> bool:
    """Delega a Verifier.verify_universal()."""
    return Verifier().verify_universal()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python verifica.py <individuale <voter_id> | universale>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "individuale":
        if len(sys.argv) < 3:
            print("Specifica voter_id")
            sys.exit(1)
        ok = verify_individual(sys.argv[2])
        sys.exit(0 if ok else 1)
    elif cmd == "universale":
        ok = verify_universal()
        sys.exit(0 if ok else 1)
    else:
        print(f"Comando sconosciuto: {cmd}")
        sys.exit(1)
