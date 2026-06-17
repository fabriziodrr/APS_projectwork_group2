"""
blockchain.py — Interfaccia Web3 per VotingContract su Ganache.
"""
import os, sys, json, hashlib, subprocess
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from config import (
    GANACHE_URL, CHAIN_ID, ETH_ACCOUNTS, PKI_DIR, CONTRACT_INFO_FILE,
    SOL_FILE, SOL_OUTPUT_DIR, ABI_FILE, BIN_FILE
)

def _get_w3():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    if not w3.is_connected():
        raise ConnectionError(f"Ganache non raggiungibile su {GANACHE_URL}")
    return w3

def compile_contract():
    """
    Compila VotingContract.sol tramite Node.js + solc module.
    Usa evmVersion=paris per compatibilità con Ganache (Shanghai hardfork).
    """
    os.makedirs(SOL_OUTPUT_DIR, exist_ok=True)
    print("[Blockchain] Compilazione VotingContract.sol (evm: paris)...")

    node_script = r"""
const solc = require('solc');
const fs   = require('fs');
const source = fs.readFileSync('contracts/VotingContract.sol', 'utf8');
const input  = {
  language: 'Solidity',
  sources:  { 'VotingContract.sol': { content: source } },
  settings: {
    evmVersion: 'paris',
    optimizer:  { enabled: true, runs: 200 },
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode'] } }
  }
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (output.errors || []).filter(e => e.severity === 'error');
if (errors.length > 0) {
  process.stderr.write(JSON.stringify(errors));
  process.exit(1);
}
const c = output.contracts['VotingContract.sol']['VotingContract'];
fs.mkdirSync('contracts_out', { recursive: true });
fs.writeFileSync('contracts_out/VotingContract.abi', JSON.stringify(c.abi));
fs.writeFileSync('contracts_out/VotingContract.bin', c.evm.bytecode.object);
console.log('OK');
"""
    script_path = os.path.join(SOL_OUTPUT_DIR, "_compile.js")
    with open(script_path, "w") as f:
        f.write(node_script)

    r = subprocess.run(["node", script_path], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Errore compilazione: {r.stderr}")

    with open(ABI_FILE) as f: abi = json.load(f)
    with open(BIN_FILE) as f: bytecode = "0x" + f.read().strip()
    print("[Blockchain] Compilazione OK.")
    return abi, bytecode

def _load_compiled():
    if not os.path.exists(ABI_FILE) or not os.path.exists(BIN_FILE):
        return compile_contract()
    with open(ABI_FILE) as f: abi = json.load(f)
    with open(BIN_FILE) as f: bytecode = "0x" + f.read().strip()
    return abi, bytecode

def deploy_contract():
    if os.path.exists(CONTRACT_INFO_FILE):
        raise FileExistsError("Contratto già deployato.")
    w3 = _get_w3()
    abi, bytecode = compile_contract()  # sempre dal sorgente .sol corrente
    dep   = ETH_ACCOUNTS["deployer"]
    aa    = ETH_ACCOUNTS["AA"]["address"]
    ar    = ETH_ACCOUNTS["AR"]["address"]
    as_   = ETH_ACCOUNTS["AS"]["address"]
    ec    = ETH_ACCOUNTS["EC"]["address"]
    print(f"[Blockchain] Deploy contratto — AA:{aa[:10]}.. AR:{ar[:10]}.. AS:{as_[:10]}.. EC:{ec[:10]}..")
    c = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = c.constructor(aa, ar, as_, ec).transact({
        "from": dep["address"], "gas": 6_700_000,
        "gasPrice": w3.to_wei("2", "gwei"), "chainId": CHAIN_ID})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    address = receipt.contractAddress
    os.makedirs(PKI_DIR, exist_ok=True)
    with open(CONTRACT_INFO_FILE, "w") as f:
        json.dump({"address": address, "abi": abi}, f, indent=2)
    print(f"[Blockchain] Contratto deployato: {address}")
    return address

def _load_contract():
    if not os.path.exists(CONTRACT_INFO_FILE):
        raise FileNotFoundError("Contratto non trovato. Esegui: python blockchain.py deploy")
    w3 = _get_w3()
    with open(CONTRACT_INFO_FILE) as f: info = json.load(f)
    return w3, w3.eth.contract(address=info["address"], abi=info["abi"])

def _send_tx(w3, fn, role, gas=500_000):
    acct = ETH_ACCOUNTS[role]
    tx = fn.build_transaction({
        "from": acct["address"], "gas": gas,
        "gasPrice": w3.to_wei("2", "gwei"),
        "nonce": w3.eth.get_transaction_count(acct["address"]),
        "chainId": CHAIN_ID})
    signed  = w3.eth.account.sign_transaction(tx, acct["private_key"])
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"TX fallita: {tx_hash.hex()}")
    return receipt

def _b32(h): return bytes.fromhex(h)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ── Funzioni contratto ────────────────────────────────────────────────────────

def register_voter(voter_id_hash):
    w3, c = _load_contract()
    _send_tx(w3, c.functions.registerVoter(_b32(voter_id_hash)), "AA")
    print(f"[Blockchain] VoterRegistered: {voter_id_hash[:16]}...")

def is_voter_registered(voter_id_hash):
    _, c = _load_contract()
    return c.functions.registeredVoters(_b32(voter_id_hash)).call()

def open_election(ts, att: bytes):
    w3, c = _load_contract()
    _send_tx(w3, c.functions.openElection(int(ts), att), "EC", 2_000_000)
    print(f"[Blockchain] ElectionOpened — ts:{int(ts)}")

def issue_token(cert_e_hash):
    w3, c = _load_contract()
    _send_tx(w3, c.functions.issueToken(_b32(cert_e_hash)), "AR")
    print(f"[Blockchain] TokenIssued: {cert_e_hash[:16]}...")

def consume_token(token_hash):
    w3, c = _load_contract()
    _send_tx(w3, c.functions.consumeToken(_b32(token_hash)), "AR")
    print(f"[Blockchain] TokenConsumed: {token_hash[:16]}...")

def submit_ballot_anchor(token_hash, ballot_hash, commit_voto, cvoto: bytes, ts):
    w3, c = _load_contract()
    receipt = _send_tx(w3, c.functions.submitBallotAnchor(
        _b32(token_hash), _b32(ballot_hash), _b32(commit_voto), cvoto, int(ts)
    ), "AR", 2_000_000)
    logs    = c.events.BallotAnchored().process_receipt(receipt)
    seq_num = logs[0]["args"]["seqNum"]
    print(f"[Blockchain] BallotAnchored — seqNum={seq_num}, H(B)={ballot_hash[:16]}...")
    return seq_num

def close_election(ts, att: bytes):
    w3, c = _load_contract()
    receipt = _send_tx(w3, c.functions.closeElection(int(ts), att), "EC", 2_000_000)
    logs    = c.events.ElectionClosed().process_receipt(receipt)
    root    = logs[0]["args"]["merkleRootUrna"].hex()
    print(f"[Blockchain] ElectionClosed — MerkleRootUrna: {root[:16]}...")
    return root

def publish_result(result, total_votes, merkle_root_bb, sig_as: bytes, att: bytes):
    w3, c = _load_contract()
    _send_tx(w3, c.functions.publishResult(
        result, total_votes, _b32(merkle_root_bb), sig_as, att
    ), "AS", 2_000_000)
    print(f"[Blockchain] ResultPublished — R={result}/{total_votes} → FINALIZED")

def declare_scrutiny_overdue():
    w3, c = _load_contract()
    _send_tx(w3, c.functions.declareScrutinyOverdue(), "EC", 100_000)
    print(f"[Blockchain] ScrutinyOverdue dichiarato.")

def advance_time(seconds: int = 20):
    """
    Avanza il clock di Ganache tramite evm_increaseTime + evm_mine.
    Usa JSON-RPC diretto (requests) per compatibilità con web3.py v6+.
    Solo per test locali — non ha effetto su reti reali.
    """
    import requests as _req
    def _rpc(method, params=None):
        r = _req.post(
            GANACHE_URL,
            json={"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"RPC {method} errore: {data['error']}")
        return data.get("result")

    _rpc("evm_increaseTime", [seconds])
    _rpc("evm_mine")
    print(f"[Blockchain] Clock Ganache avanzato di {seconds}s.")

def get_state():
    _, c = _load_contract()
    return ["CREATED", "OPEN", "CLOSED", "FINALIZED", "SCRUTINY_OVERDUE"][c.functions.state().call()]

def get_ballot_count():
    _, c = _load_contract()
    return c.functions.ballotCount().call()

def get_ballot_anchor(idx):
    _, c = _load_contract()
    seq, bh, cv, cvoto, ts = c.functions.getBallotAnchor(idx).call()
    return {
        "seqNum":    seq,
        "ballotHash": bh.hex(),
        "commitVoto": cv.hex(),
        "cvoto":      cvoto,
        "ts":         ts,
    }

def get_all_ballot_anchors():
    return [get_ballot_anchor(i) for i in range(get_ballot_count())]

def get_election_info():
    _, c = _load_contract()
    return {
        "state":          get_state(),
        "tsApertura":     c.functions.tsApertura().call(),
        "merkleRootUrna": c.functions.merkleRootUrna().call().hex(),
        "tsChiusura":     c.functions.tsChiusura().call(),
        "finalResult":    c.functions.finalResult().call(),
        "totalVotes":     c.functions.totalVotes().call(),
        "merkleRootBB":   c.functions.merkleRootBB().call().hex(),
        "ballotCount":    get_ballot_count(),
    }

# ── Funzioni Merkle (usate da as_.py e verifica.py) ───────────────────────────

def _keccak(data: bytes) -> bytes:
    """keccak256 tramite Web3 built-in."""
    return bytes(Web3.keccak(data))

def merkle_root_keccak(leaves: list) -> bytes:
    """
    Radice Merkle con keccak256. Padding nodo dispari (duplica l'ultimo).
    """
    nodes = list(leaves)
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [_keccak(nodes[i] + nodes[i + 1]) for i in range(0, len(nodes), 2)]
    return nodes[0]

def compute_merkle_root_urna(anchors: list) -> str:
    """
    Ricalcola MerkleRootUrna dagli ancoraggi — deve coincidere con il valore
    calcolato on-chain dal contratto in closeElection().
    Foglie: keccak256(ballotHash_bytes32 || commitVoto_bytes32)
    """
    if not anchors:
        return _keccak(b"empty").hex()
    leaves = [
        _keccak(bytes.fromhex(a["ballotHash"]) + bytes.fromhex(a["commitVoto"]))
        for a in anchors
    ]
    return merkle_root_keccak(leaves).hex()

def compute_merkle_root_bb(pairs: list) -> str:
    """
    Calcola MerkleRootBB per il Bulletin Board.
    Foglie: keccak256(bytes([v]) || bytes.fromhex(commit_voto))
    pairs: lista di (v: int, commit_voto: str hex-64)
    """
    if not pairs:
        return _keccak(b"empty").hex()
    leaves = [_keccak(bytes([v]) + bytes.fromhex(c)) for v, c in pairs]
    return merkle_root_keccak(leaves).hex()

# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cmds = {
        "deploy":       "Compila e deploya il contratto",
        "status":       "Stato corrente dell'elezione",
        "list-ballots": "Elenca tutti gli ancoraggi on-chain",
    }
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print("Uso: python blockchain.py <deploy|status|list-ballots>")
        for cmd, desc in cmds.items():
            print(f"  {cmd:<16} {desc}")
        sys.exit(1)

    if sys.argv[1] == "deploy":
        deploy_contract()
    elif sys.argv[1] == "status":
        for k, v in get_election_info().items():
            print(f"  {k:<18}: {v}")
    elif sys.argv[1] == "list-ballots":
        anchors = get_all_ballot_anchors()
        if not anchors:
            print("Nessuna scheda ancorata.")
        for a in anchors:
            print(f"  [{a['seqNum']}] H(B)={a['ballotHash'][:24]}... "
                  f"commit={a['commitVoto'][:16]}...")
