# APS Project Work Group 2

Project work universitario per il corso di **Algoritmi e Protocolli per la Sicurezza**
presso l'**Universita degli Studi di Salerno**, corso **ML-32**.

Questo repository contiene la soluzione progettuale e il prototipo di un protocollo di voto elettronico
basato su crittografia asimmetrica, commitment, schema di Shamir e smart contract Ethereum.

## Descrizione del progetto

Il sistema modella un flusso di voto con i seguenti obiettivi:

- registrazione degli elettori tramite infrastruttura PKI;
- autenticazione verso l'autorita di raccolta;
- emissione di token univoci per prevenire il doppio voto;
- cifratura del voto e ancoraggio immutabile su blockchain;
- scrutinio con ricostruzione controllata della chiave di decifratura;
- verifiche sia individuali sia universali del risultato finale.

Le principali primitive usate nel progetto sono RSA-OAEP, RSA con SHA-256 per le firme, SHA-256 per i commitment,
AES-256-GCM per la trasmissione protetta delle share e lo schema di Shamir per la condivisione della chiave.

## Contenuti principali

- documentazione progettuale in `Documentation/Project_doc.pdf`;
- prototipo software del protocollo;
- smart contract `VotingContract` per il registro pubblico immutabile;
- strumenti di verifica individuale e universale.

## Obiettivi di sicurezza

- confidenzialita del voto;
- integrita della scheda e del risultato;
- unicita del voto;
- verificabilita individuale e universale;
- tracciabilita pubblica delle attestazioni;
- riduzione del trust verso le autorita di sistema.

## Panoramica tecnica

- `AA`: autorita di autenticazione;
- `AR`: autorita di raccolta;
- `AS`: autorita di scrutinio;
- `EC`: ente certificatore legale;
- `VotingContract`: smart contract Ethereum che gestisce stati, ancoraggi e pubblicazione del risultato.

## English

This repository hosts the university project and prototype for the course **Algorithms and Protocols for Security**
at the **University of Salerno**, degree program **ML-32**.

The project implements a blockchain-based electronic voting protocol using public-key cryptography,
commitments, Shamir secret sharing, and an Ethereum smart contract.

### Project overview

The system is designed to provide:

- voter registration through a PKI infrastructure;
- authentication toward the collecting authority;
- unique token issuance to prevent double voting;
- encrypted ballots anchored immutably on-chain;
- tallying with controlled reconstruction of the decryption key;
- both individual and universal verification of the final result.

The main primitives used in the project are RSA-OAEP, RSA with SHA-256 signatures, SHA-256 commitments,
AES-256-GCM for protected share transfer, and Shamir secret sharing for key distribution.

### Main contents

- project documentation in `Documentation/Project_doc.pdf`;
- software prototype of the protocol;
- `VotingContract` smart contract for the immutable public ledger;
- tools for individual and universal verification.

### Security goals

- ballot confidentiality;
- ballot and result integrity;
- uniqueness of the vote;
- individual and universal verifiability;
- public traceability of attestations;
- reduced trust in the system authorities.

### Technical overview

- `AA`: authentication authority;
- `AR`: collecting authority;
- `AS`: tallying authority;
- `EC`: legal certification authority;
- `VotingContract`: Ethereum smart contract that manages states, anchors, and result publication.
