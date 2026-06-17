// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VotingContract
 * @notice Registro pubblico immutabile del ciclo di vita dell'elezione.
 *         Implementa la macchina a stati: CREATED → OPEN → CLOSED → FINALIZED.
 *         Non esegue logica crittografica: riceve dati già prodotti off-chain
 *         e li cristallizza in modo immutabile e verificabile.
 */
contract VotingContract {

    // ── Macchina a stati ─────────────────────────────────────────────────────
    //   CREATED → OPEN → CLOSED → FINALIZED
    //                      ↓
    //               SCRUTINY_OVERDUE  (se AS non pubblica entro la deadline)
    enum State { CREATED, OPEN, CLOSED, FINALIZED, SCRUTINY_OVERDUE }
    State public state;

    // ── Costanti ─────────────────────────────────────────────────────────────
    uint256 public constant DELTA_SCRUTINIO = 10; // 7 giorni in secondi

    // ── Indirizzi autorità (immutabili dopo il deploy) ────────────────────────
    address public immutable addrAA;
    address public immutable addrAR;
    address public immutable addrAS;
    address public immutable addrEC;

    // ── Mapping on-chain ─────────────────────────────────────────────────────
    mapping(bytes32 => bool) public registeredVoters;  // H(ID_elettore) → bool
    mapping(bytes32 => bool) public issuedTokens;      // H(Cert_e)      → bool
    mapping(bytes32 => bool) public usedTokens;        // H(token)       → bool

    // ── Struttura ancoraggio scheda ───────────────────────────────────────────
    struct BallotAnchor {
        uint256 seqNum;
        bytes32 tokenHash;
        bytes32 ballotHash;
        bytes32 commitVoto;
        bytes   cvoto;           // RSA-OAEP ciphertext
        uint256 tsRegistrazione;
    }
    BallotAnchor[] public ballotAnchors;

    // ── Dati elezione ─────────────────────────────────────────────────────────
    uint256 public scrutinyDeadline;  // block.timestamp oltre il quale EC può dichiarare inadempienza
    uint256 public tsApertura;
    bytes   public attApertura;
    bytes32 public merkleRootUrna;
    uint256 public tsChiusura;
    bytes   public attChiusura;
    int256  public finalResult;
    uint256 public totalVotes;
    bytes32 public merkleRootBB;
    bytes   public sigAS;
    bytes   public attRisultato;

    // ── Eventi ────────────────────────────────────────────────────────────────
    event VoterRegistered(bytes32 indexed voterIdHash);
    event ElectionOpened(uint256 tsApertura);
    event TokenIssued(bytes32 indexed certHash);
    event TokenConsumed(bytes32 indexed tokenHash);
    event BallotAnchored(uint256 indexed seqNum, bytes32 ballotHash,
                         bytes32 commitVoto, uint256 ts);
    event ElectionClosed(uint256 tsChiusura, bytes32 merkleRootUrna);
    event ResultPublished(int256 result, uint256 totalVotes, bytes32 merkleRootBB);
    event ScrutinyOverdue(uint256 ts);

    // ── Modificatori ─────────────────────────────────────────────────────────
    modifier onlyAA() { require(msg.sender == addrAA, "Solo AA"); _; }
    modifier onlyAR() { require(msg.sender == addrAR, "Solo AR"); _; }
    modifier onlyAS() { require(msg.sender == addrAS, "Solo AS"); _; }
    modifier onlyEC() { require(msg.sender == addrEC, "Solo EC"); _; }
    modifier inState(State _s) {
        require(state == _s, string(abi.encodePacked(
            "Stato errato: atteso ", _stateName(_s))));
        _;
    }

    // ── Costruttore ───────────────────────────────────────────────────────────
    constructor(address _aa, address _ar, address _as, address _ec) {
        addrAA      = _aa;
        addrAR      = _ar;
        addrAS      = _as;
        addrEC      = _ec;
        state       = State.CREATED;
        finalResult = -1;
    }

    // ── Fase CREATED ─────────────────────────────────────────────────────────

    /**
     * @notice Registra un elettore (anti-duplicato on-chain).
     *         Sezione 11.3 — invocata da AA.
     */
    function registerVoter(bytes32 voterIdHash)
        external onlyAA inState(State.CREATED)
    {
        require(!registeredVoters[voterIdHash], "Elettore gia registrato");
        registeredVoters[voterIdHash] = true;
        emit VoterRegistered(voterIdHash);
    }

    /**
     * @notice Apre l'elezione. Sezione 12 — invocata da EC.
     */
    function openElection(uint256 _ts, bytes calldata _att)
        external onlyEC inState(State.CREATED)
    {
        tsApertura  = _ts;
        attApertura = _att;
        state       = State.OPEN;
        emit ElectionOpened(_ts);
    }

    // ── Fase OPEN ────────────────────────────────────────────────────────────

    /**
     * @notice Registra l'emissione di un token (anti-emissione-multipla).
     *         Sezione 13.3 — invocata da AR.
     */
    function issueToken(bytes32 certHash)
        external onlyAR inState(State.OPEN)
    {
        require(!issuedTokens[certHash], "Token gia emesso per questo certificato");
        issuedTokens[certHash] = true;
        emit TokenIssued(certHash);
    }

    /**
     * @notice Consuma un token (gate anti-doppio-voto).
     *         Sezione 14.2.2 — invocata da AR prima di submitBallotAnchor.
     */
    function consumeToken(bytes32 tokenHash)
        external onlyAR inState(State.OPEN)
    {
        require(!usedTokens[tokenHash], "Token gia consumato");
        usedTokens[tokenHash] = true;
        emit TokenConsumed(tokenHash);
    }

    /**
     * @notice Ancora una scheda on-chain.
     *         Sezione 14.2.2 — invocata da AR dopo consumeToken.
     *         Restituisce seqNum assegnato deterministicamente dal contratto.
     */
    function submitBallotAnchor(
        bytes32 _tokenHash,
        bytes32 _ballotHash,
        bytes32 _commitVoto,
        bytes   calldata _cvoto,
        uint256 _ts
    ) external onlyAR inState(State.OPEN) returns (uint256) {
        require(usedTokens[_tokenHash], "Token non consumato: chiama consumeToken prima");

        uint256 seqNum = ballotAnchors.length;
        ballotAnchors.push(BallotAnchor({
            seqNum:          seqNum,
            tokenHash:       _tokenHash,
            ballotHash:      _ballotHash,
            commitVoto:      _commitVoto,
            cvoto:           _cvoto,
            tsRegistrazione: _ts
        }));

        emit BallotAnchored(seqNum, _ballotHash, _commitVoto, _ts);
        return seqNum;
    }

    // ── Fase CLOSED ──────────────────────────────────────────────────────────

    /**
     * @notice Chiude l'elezione e calcola MerkleRootUrna.
     *         Sezione 15.1 — invocata da EC.
     *         Imposta scrutinyDeadline = ora + DELTA_SCRUTINIO.
     */
    function closeElection(uint256 _ts, bytes calldata _att)
        external onlyEC inState(State.OPEN)
    {
        merkleRootUrna   = _computeMerkleRootUrna();
        tsChiusura       = _ts;
        attChiusura      = _att;
        scrutinyDeadline = block.timestamp + DELTA_SCRUTINIO;
        state            = State.CLOSED;
        emit ElectionClosed(_ts, merkleRootUrna);
    }

    /**
     * @notice Dichiara l'inadempienza di AS se la deadline è trascorsa.
     *         Invocabile da EC solo in stato CLOSED dopo scrutinyDeadline.
     */
    function declareScrutinyOverdue()
        external onlyEC inState(State.CLOSED)
    {
        require(block.timestamp > scrutinyDeadline, "Deadline scrutinio non ancora raggiunta");
        state = State.SCRUTINY_OVERDUE;
        emit ScrutinyOverdue(block.timestamp);
    }

    /**
     * @notice Pubblica il risultato finale.
     *         Sezione 16.2 — invocata da AS.
     */
    function publishResult(
        int256  _result,
        uint256 _totalVotes,
        bytes32 _merkleRootBB,
        bytes   calldata _sigAS,
        bytes   calldata _attRisultato
    ) external onlyAS inState(State.CLOSED) {
        finalResult    = _result;
        totalVotes     = _totalVotes;
        merkleRootBB   = _merkleRootBB;
        sigAS          = _sigAS;
        attRisultato   = _attRisultato;
        state          = State.FINALIZED;
        emit ResultPublished(_result, _totalVotes, _merkleRootBB);
    }

    // ── Letture pubbliche ─────────────────────────────────────────────────────

    function ballotCount() external view returns (uint256) {
        return ballotAnchors.length;
    }

    function getBallotAnchor(uint256 idx) external view returns (
        uint256 seqNum,
        bytes32 ballotHash,
        bytes32 commitVoto,
        bytes memory cvoto,
        uint256 ts
    ) {
        BallotAnchor storage a = ballotAnchors[idx];
        return (a.seqNum, a.ballotHash, a.commitVoto, a.cvoto, a.tsRegistrazione);
    }

    // ── Merkle tree interno ───────────────────────────────────────────────────

    function _computeMerkleRootUrna() internal view returns (bytes32) {
        uint256 n = ballotAnchors.length;
        if (n == 0) return keccak256("empty");

        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = keccak256(abi.encodePacked(
                ballotAnchors[i].ballotHash,
                ballotAnchors[i].commitVoto
            ));
        }
        return _merkleRoot(leaves);
    }

    function _merkleRoot(bytes32[] memory nodes) internal pure returns (bytes32) {
        while (nodes.length > 1) {
            uint256 len    = nodes.length;
            uint256 newLen = (len + 1) / 2;
            bytes32[] memory next = new bytes32[](newLen);
            for (uint256 i = 0; i < newLen; i++) {
                uint256 l = 2 * i;
                uint256 r = (l + 1 < len) ? l + 1 : l;
                next[i]   = keccak256(abi.encodePacked(nodes[l], nodes[r]));
            }
            nodes = next;
        }
        return nodes[0];
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    function _stateName(State _s) internal pure returns (string memory) {
        if (_s == State.CREATED)          return "CREATED";
        if (_s == State.OPEN)             return "OPEN";
        if (_s == State.CLOSED)           return "CLOSED";
        if (_s == State.FINALIZED)        return "FINALIZED";
        return "SCRUTINY_OVERDUE";
    }
}
