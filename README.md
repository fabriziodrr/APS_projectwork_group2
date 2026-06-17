# APS Voting System

Sistema di voto elettronico crittograficamente sicuro sviluppato come progetto per il corso di **Algoritmi e Protocolli per la Sicurezza (APS)**. Implementa un protocollo di voto remoto che garantisce anonimato, integrità, verificabilità individuale e universale, con ancoraggio su blockchain Ethereum tramite smart contract.

---

## Indice

- [Panoramica](#panoramica)
- [Architettura](#architettura)
- [Proprietà di Sicurezza](#proprietà-di-sicurezza)
- [Strumenti Crittografici](#strumenti-crittografici)
- [Struttura del Progetto](#struttura-del-progetto)
- [Requisiti](#requisiti)
- [Installazione](#installazione)
- [Utilizzo](#utilizzo)
- [Flusso del Protocollo](#flusso-del-protocollo)
- [Smart Contract](#smart-contract)

---

## Panoramica

Il sistema simula un referendum elettronico completo, dalla registrazione degli elettori fino alla pubblicazione del risultato verificabile. Ogni fase del protocollo è eseguita da un'autorità dedicata con responsabilità separate, senza che nessun singolo attore possa compromettere la segretezza o l'integrità del voto.

Il voto è cifrato lato client, trasmesso a un'Autorità di Raccolta, ancorato su una blockchain Ethereum locale (Ganache) tramite un apposito smart contract (`VotingContract`), e decifrato solo a scrutinio concluso dall'Autorità di Scrutinio tramite un meccanismo di **threshold decryption** (Shamir t=2, n=3).

---

## Architettura

Il sistema prevede i seguenti attori con ruoli separati:

| Attore                         | Sigla | Responsabilità |
|--------------------------------|-------|-----------------------------------------------------------------------------------------------------------------------|
| **Certification Authority**    | CA    | Radice di fiducia PKI; emette i certificati X.509 di tutte le autorità                                                |
| **Autorità di Autenticazione** | AA    | Verifica l'identità degli elettori e rilascia le credenziali di voto (certificato `Cert_e`)                           |
| **Autorità di Raccolta**       | AR    | Riceve i voti cifrati, emette le ricevute e ancora le schede on-chain via `submitBallotAnchor`                        |
| **Autorità di Scrutinio**      | AS    | A urne chiuse, recupera i voti dalla blockchain, li decifra (ricostruendo la chiave via Shamir) e pubblica il risultato  con   prove crittografiche |
| **Ente Certificatore Legale**  | EC    | Terza parte indipendente; attesta on-chain l'apertura e la chiusura delle urne, firma il risultato                    |
| **Elettore**                   | —     | Si registra, ottiene un token di sessione monouso, esprime il voto cifrato e verifica a posteriori l'inclusione nel conteggio  |

**Ethereum (Ganache)** funge da registro pubblico immutabile: le autorità pubblicano dati critici tramite `VotingContract`, verificabile da chiunque senza credenziali.

---

## Proprietà di Sicurezza

### Confidenzialità
- Il voto rimane segreto; nessun singolo attore può associare l'identità dell'elettore alla sua preferenza (**pseudo-anonimato**)
- I dati personali degli elettori sono accessibili solo ad AA; AR e AS operano su dati cifrati
- I voti sono cifrati con RSA-OAEP (CPA-secure) verso la chiave pubblica di AS

### Integrità
- I voti non possono essere alterati, soppressi o duplicati dopo la registrazione
- Il doppio voto è impedito on-chain dal mapping `usedTokens` nello smart contract
- Solo elettori con `Cert_e` valido emesso da AA possono ottenere un token di sessione
- Il risultato finale riflette matematicamente i soli voti validi

### Trasparenza
- Protocollo e codice sorgente pubblicamente noti
- Verificabilità **individuale**: ogni elettore può controllare che il proprio voto sia incluso nel conteggio
- Verificabilità **universale**: chiunque può verificare il risultato senza credenziali, leggendo direttamente dalla blockchain
- Apertura e chiusura urne attestate dall'EC on-chain; risultato firmato e ancorato su Ethereum

### Resistenza agli attacchi
- **Replay attack**: nonce + timestamp con finestra di 5 minuti
- **Doppio voto**: token monouso registrati on-chain
- **Collusion**: nessuna singola autorità possiede la chiave di decifratura completa (Shamir t=2, n=3)
- **Coercizione / vendita del voto**: nessun meccanismo di revoca o sostituzione del voto

---

## Strumenti Crittografici

| Strumento | Utilizzo |
|-----------|----------|
| **RSA-FDH** | Autenticazione elettori, firma di voto e risultato |
| **RSA-OAEP** | Cifratura del voto verso AS (CPA-secure) |
| **PKI / X.509** | Distribuzione chiavi pubbliche delle autorità |
| **SHA-256** | Integrità messaggi, hash certificati, Merkle tree on-chain, commitment `SHA-256(v ‖ r_commit)` |
| **Shamir Secret Sharing (t=2, n=3)** | Distribuzione chiave di decifratura AS tra 3 garanti; bastano 2 per lo scrutinio |
| **Nonce / Timestamp** | Prevenzione replay, freschezza messaggi |
| **Ethereum Smart Contract** | Registro immutabile per attestazioni, token, voti cifrati, Bulletin Board e controllo anti-doppio-voto |

---

## Struttura del Progetto

```
demo/
├── config.py          # Configurazione condivisa (percorsi PKI, parametri crittografici, account Ganache)
├── blockchain.py      # Interfaccia Web3 per VotingContract su Ganache (deploy, compile, query)
├── ca.py              # Certification Authority: generazione radice PKI
├── aa.py              # Autorità di Autenticazione: registrazione elettori, emissione Cert_e
├── ar.py              # Autorità di Raccolta: ricezione voti, emissione token, ancoraggio on-chain
├── as_.py             # Autorità di Scrutinio: ricostruzione chiave (Shamir), decifratura, tally
├── ec.py              # Ente Certificatore Legale: apertura/chiusura urne, attestazioni
├── elettore.py        # Modulo elettore: keygen, registrazione, autenticazione, espressione voto
├── verifica.py        # Verificabilità individuale e universale
├── crypto_utils.py    # Primitive crittografiche comuni (RSA-OAEP, FDH, SHA-256, X.509)
├── shamir_setup.py    # Setup Shamir: splitting chiave AS tra i 3 garanti
├── gui.py             # Interfaccia grafica (Tkinter) per l'interazione manuale
├── start_all.py       # Demo completa automatizzata (setup → registrazione → voto → scrutinio → verifica)
├── benchmark.py       # Benchmark delle operazioni crittografiche
├── contracts/
│   └── VotingContract.sol   # Smart contract Solidity (macchina a stati dell'elezione)
├── contracts_out/           # Output compilazione Solidity (ABI + bytecode) — generato automaticamente
└── aps-voting-pki/          # PKI e wallet elettori — generato automaticamente al primo run
```

---

## Requisiti

- **Python** >= 3.10
- **Node.js** >= 18 (per la compilazione Solidity tramite `solc`)
- **Ganache** (blockchain Ethereum locale) — configurato su `http://127.0.0.1:7545` con `--deterministic`

### Dipendenze Python

```bash
pip install web3 cryptography
```

### Dipendenze Node.js

```bash
npm install
```

Installa `solc` v0.8.x (già specificato in `package.json`).

---

## Installazione

```bash
# 1. Clona il repository
git clone <url-repo>
cd demo

# 2. Installa dipendenze Python
pip install web3 cryptography

# 3. Installa dipendenze Node.js (compilatore Solidity)
npm install

# 4. Avvia Ganache in modalità deterministica (su un altro terminale)
ganache --deterministic --port 7545
```

> Gli account Ethereum in `config.py` corrispondono esattamente agli account generati da `ganache --deterministic`. Non modificare le chiavi private senza aggiornare `config.py`.

---

## Utilizzo

### Demo completa automatizzata

Esegue l'intero protocollo in sequenza: setup PKI, registrazione, apertura urne, votazione, chiusura, scrutinio e verifica.

```bash
python start_all.py
```

Per ripristinare lo stato e rieseguire da zero:

```bash
python start_all.py --clean
```

### Interfaccia grafica

```bash
python gui.py
```

Permette di interagire manualmente con le singole fasi del protocollo (registrazione, autenticazione, espressione del voto, verifica).


### Singoli moduli

```bash
python blockchain.py deploy   # Compila e deploya VotingContract su Ganache
python ca.py setup            # Inizializza la CA
python aa.py setup            # Inizializza AA
python ar.py setup            # Inizializza AR
python as_.py setup           # Inizializza AS e distribuisce le share Shamir
python ec.py setup            # Inizializza EC
```

---

## Flusso del Protocollo

```
[Setup]
  CA         → genera radice PKI, emette certificati ad AA, AR, AS, EC
  AS         → genera coppia di chiavi; la chiave privata è splittata in 3 share (Shamir t=2, n=3)
  blockchain → compila VotingContract.sol e lo deploya su Ganache

[Registrazione]
  Elettore   → genera coppia RSA + richiesta di certificato
  AA         → verifica identità, emette Cert_e, registra on-chain (registerVoter)

[Apertura urne]
  EC         → firma Att_apertura, invoca openElection → stato: OPEN

[Autenticazione e voto]
  Elettore   → presenta Cert_e ad AR, riceve token monouso
  AR         → registra token on-chain (issueToken)
  Elettore   → cifra il voto con pk_AS (RSA-OAEP), firma con sk_e (FDH)
               calcola commitment SHA-256(voto ‖ r_commit)
  AR         → verifica firma, consuma token on-chain (consumeToken)
               ancora scheda on-chain con C_voto (submitBallotAnchor)
               rilascia ricevuta all'elettore

[Chiusura urne]
  EC         → calcola Merkle root dell'urna, firma Att_chiusura
               invoca closeElection → stato: CLOSED

[Scrutinio]
  Guaranti   → trasmettono ad AS le proprie share (cifrate con pk_AS_recv e firmate)
  AS         → raccoglie >= 2 share, ricostruisce sk_AS via Shamir
               recupera C_voto dalla blockchain
               decifra tutti i voti, calcola il risultato
               pubblica Bulletin Board e Merkle root on-chain (publishResult)
               → stato: FINALIZED

[Verifica individuale]
  Elettore   → controlla che il proprio commitment sia nel Bulletin Board
               verifica la firma della ricevuta rilasciata da AR
               confronta C_voto on-chain con quello ricevuto nella ricevuta

[Verifica universale]
  Chiunque   → legge C_voto dalla blockchain
               verifica Merkle root urna firmata da EC
               verifica Merkle root BB firmata da AS
               confronta risultato on-chain con ricalcolo manuale dai voti decifrati
```

---

## Smart Contract

`VotingContract.sol` modella il ciclo di vita dell'elezione come una **macchina a stati** con cinque stati:

| Stato              | Descrizione                                                                                                                 |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `CREATED`          | Deploy iniziale. AA registra gli elettori (`registerVoter`)                                                                 |
| `OPEN`             | EC ha aperto le urne. AR emette token (`issueToken`), consuma token (`consumeToken`) e ancora schede (`submitBallotAnchor`) |
| `CLOSED`           | EC ha chiuso le urne. Raccolta bloccata; AS può pubblicare il risultato entro `scrutinyDeadline`                            |
| `FINALIZED`        | Risultato pubblicato. Nessuna scrittura ulteriore; tutte le letture disponibili                                             |
| `SCRUTINY_OVERDUE` | Deadline scaduta senza pubblicazione. Evidenza pubblica e immutabile del mancato adempimento di AS                          |

Il contratto è compilato con **Solidity 0.8.x** (EVM target: `paris` per compatibilità con Ganache) e deployato localmente su Ganache prima di ogni sessione di voto.
