# Qstamp

Qstamp is a post quantum time stamping SDK for the Quantova network. It produces evidence that a record existed in an exact form no later than a stated moment, and it lets any third party confirm that evidence without trusting the party that created it.

Qstamp proves records without disclosing them. The records stay private on the systems of the organisation that holds them. Only a salted cryptographic commitment is written to the chain, and no record content, prompt, personal data or payment detail is ever published.

## What is published and what stays private

Qstamp is designed for organisations that must prove what their systems did while keeping the underlying data confidential.

The following stay on the systems of the organisation and are never sent by the SDK to Quantova Inc, to the network or to any other party.

1. The records themselves, including prompts and instructions, agent inputs and outputs, reasoning, tool calls, documents, model files, personal data and payment details.
2. The fingerprint of each record and the random salt bound to it.
3. The receipts.

The following are written to the chain, where anyone can read them.

1. One 32 byte commitment for each batch, computed from the salted fingerprints of every record in the batch.
2. The record kind, a number such as 6 for an AI agent action.
3. The ordinary data of every transaction, namely the signing account, the contract, the block, the time and the fee.

The commitment is the output of SHA3 over salted values. It cannot be reversed into any record, and because every record carries a fresh 256 bit random salt, nobody can confirm a guess about a record, even a short or predictable one. The commitment does not reveal how many records a batch holds or what they contain.

A record is disclosed only when its holder chooses to produce it, for example to a court, a regulator or an auditor, together with its receipt. The verifier then checks the record against the commitment on the chain.

Transparency in Qstamp therefore means that the proof can be inspected by anyone. It does not mean that the data is open.

## Purpose

Almost every digital signature in use today relies on elliptic curve or RSA cryptography. A sufficiently capable quantum computer will be able to forge such signatures. From that point a forged signature and a genuine one become indistinguishable, unless the genuine record can be shown to have existed before the break.

Qstamp provides that showing. Each anchored commitment is carried by a transaction signed with the Module Lattice Digital Signature Algorithm (FIPS 204, parameter set 65) and finalised by a validator committee that signs every block with the same algorithm. The Quantova network has used these signatures from its first block, so the record of when a commitment was made does not depend on any primitive that a quantum computer is known to break.

Typical uses include financial and trading records, contracts and loan documents, regulatory filings, official registers, software releases, AI models and datasets, and records of decisions taken by AI systems.

## Cryptographic construction

1. Fingerprint. Each record is reduced to a 32 byte digest using SHA3 with a 256 bit output (FIPS 202) by default, or SHA2 with a 256 bit output (FIPS 180 revision 4) where an existing system already uses it. The algorithm is bound into the leaf so that a digest produced by one algorithm can never be presented as a digest of the other.

2. Leaf. Each digest is combined with a fresh 32 byte random salt drawn from the operating system generator. The leaf value is the SHA3 hash of the byte 0x00, the domain label QSTAMP/LEAF/V1, the algorithm identifier, the digest and the salt. The salt prevents any party who sees the chain from confirming a guess about the content of a low entropy record.

3. Batch tree. Leaves are arranged in a binary hash tree following the construction of RFC 9162 section 2.1. Interior nodes are the SHA3 hash of the byte 0x01 followed by the left and right children. Distinct leading bytes separate leaves from nodes and remove second preimage ambiguity. One batch holds up to 1048576 records.

4. Commitment. The value written to the chain is the SHA3 hash of the byte 0x02, the domain label QSTAMP/ROOT/V1, the genesis hash of the chain, the contract address, the signer address, the record kind as an unsigned 64 bit big endian integer, the batch size as an unsigned 64 bit big endian integer and the tree root. Binding all of these means the batch cannot be replayed on another chain or contract, cannot be claimed by another signer who copies the commitment from a pending transaction, and cannot have its kind, size or record positions altered after anchoring.

5. Anchoring. A single transaction calls the Qstamp contract with the commitment and a record kind, and nothing else about the batch is sent. The contract emits one event that holds the address of the signer, the commitment and the kind. The contract keeps no state, holds no funds and has no owner or upgrade path. The Quantova network admits only contract code signed by its attested compiler, so the deployed contract cannot be replaced by altered code at the same address.

The contract also offers the entry stamp_until, which takes a deadline in seconds since 1970 and records the commitment only while the block time is at or before that deadline. It emits an event that also holds the deadline, and the receipt then carries it in the field until. The stamp option until uses this entry. A record that must be anchored before an expiry, such as an action under a mandate, can therefore never be anchored after it.

6. Receipt. Each record receives its own receipt. A receipt holds the chain identity, the contract address, the record kind, the algorithm, digest and salt, the inclusion path, the tree root and the anchoring transaction, block height, block identifier, block time and signer address. A receipt contains no part of the record.

## What a receipt establishes

When verification succeeds, the following statements hold.

1. The content presented to the verifier has exactly the digest held in the receipt.
2. That digest, with its salt and algorithm, is a leaf of a batch tree of the stated size at the stated position.
3. The commitment to that tree and size was recorded by the official Qstamp contract in the stated block, in a transaction signed by the stated address.
4. That block is final on the chain whose name and genesis hash appear in the receipt.
5. The record therefore existed in exactly this form no later than the time of that block.

## What a receipt does not establish

1. It does not show that the content is true, lawful or correct. It shows only that the content existed unchanged at a point in time.
2. It does not show that the record did not exist earlier. It sets a latest possible time, not an earliest one.
3. It does not identify a natural or legal person. The signer is a chain address, and linking an address to an organisation is a separate attestation.
4. On its own it does not satisfy the requirements of any regulation for an organisation, and it is not a qualified electronic time stamp within the meaning of the eIDAS regulation unless issued through a certified trust service provider.

## Trust model of this release

The checks on the record, the salt, the inclusion path and the commitment are performed locally and depend on no outside party.

The anchor itself is then confirmed by a finality proof, and a receipt is reported valid only when that proof succeeds. Endpoints that agree, official or not, are never a proof on their own.

1. Finality proof. The verifier asks the endpoints for the header of the anchoring block, the finality certificate of the validators and the inclusion proof of the stamp event under the event root of that header. It checks the certificate against the validator roster pinned in this release for the epoch of the block and requires signatures from validators holding more than two thirds of its stake, so a certificate carried by exactly two thirds is not a proof, and a total stake equal to the pinned roster. Every signer must also prove its committee membership against the sortition root that the pinned roster gives it, so a certificate whose membership credentials were altered or taken from another validator is refused. It then confirms that the proven event is exactly the stamp event of the receipt, with its contract, signer, kind, commitment and deadline. Because every step is checked cryptographically against the pinned roster, such a proof holds even when every endpoint consulted is run by an attacker, and the result carries the trust value `finality-proof`. The verifier reads the header bytes and the certificate from `get_finality`, the event leaf and its path from `get_event_proof`, and refuses replies whose height, index, chain, header hash, event root or path length do not match. From the endpoint that served the certificate the verifier then requests the inclusion proof of the anchoring transaction with `get_transaction_proof`, checks that the transaction whose id the receipt names is included under the transaction root of the certified header, and reads the proven transaction to confirm that it is a contract call signed by the signer of the receipt for this chain, sent to the contract of the receipt and carrying the commitment, kind and deadline of the stamp. The checks use the proof functions `verifyFinality`, `verifyEvent`, `decodeEvent` and `verifyTransaction` of `@quantovainc/qcore` 0.9.1, and a client core that lacks any of them leaves the anchor unproven. Before any proof is used the verifier hands the client core a known certificate of the chain, which must verify under its own genesis and be refused under another, and every certificate it then relies on must also be refused under a fresh random genesis, so a client core that does not bind certificates to the genesis is detected. The inclusion of the event and of the transaction is checked again by the verifier itself, so the proof functions of the core are never the only check. The certified header must be the block the receipt names. Every validator signs the chain id followed by the genesis hash, and the verifier checks each certificate against the genesis pinned in this release, never against a genesis an endpoint names, so a chain relaunched under the same name with the same validator keys cannot certify a block for the pinned genesis. The rosters are pinned together with that genesis, and a proof is used only when the endpoint that served it names that genesis in `node_info` and the receipt names it too. When an endpoint whose certificate verifies against the pinned roster names another genesis or another chain name, its proof is not used, because the certificate is bound to the pinned genesis and the name is only the word of the endpoint. An endpoint that names no genesis is not used. Because the genesis an endpoint names is only its own word, the rosters are always pinned together with a checkpoint, the height and header hash of a certified block of the pinned chain or the genesis header itself, and a network that pins rosters without a checkpoint is refused. The endpoint must serve that header before its proof is used, and an endpoint whose certified header at that height is another one is taken to serve another chain and makes the receipt invalid. Every endpoint that serves a finality proof is checked, and when verified certificates from the pinned roster certify two different blocks at the height of the anchor, the validators have equivocated and the receipt is reported invalid. Once the transaction is proven in this way the receipt is valid whatever any endpoint reports about the transaction. A transaction proof that does not lead to the certified transaction root, that answers for another transaction or that proves a transaction other than the one the receipt describes makes the receipt invalid, unless another endpoint serves a proof that holds. Only when the gateway serves no transaction inclusion proof does the verifier fall back to the endpoints, and then at least one endpoint must confirm the anchoring transaction and none may report that it differs, otherwise the result is indeterminate. In that fallback alone a single endpoint that lies or lags can keep a proven receipt from being reported valid, and in no case can an endpoint make a forged receipt valid. A pinned roster is chosen from the height and the pinned epoch length, never from the epoch an endpoint names, and while the epoch length is not pinned no roster is used. While no roster is pinned for a network, or the block lies in an epoch whose roster is not pinned, the anchor stays unproven.
2. Official quorum. The verifier consults the official endpoints of the network, each of which names the operator that runs it. When official endpoints of at least two different operators return identical chain data the result carries the trust value `official-quorum`, but the receipt stays unproven, because agreeing endpoints are not a cryptographic proof. On a network that pins validator rosters or sets `requireFinality` to true the trust value is `none`. The result is indeterminate when an endpoint served a certificate that does not verify.

A receipt whose chain data matches what the consulted endpoints report, but which no finality proof covers, is reported with the status `unproven`. Its trust value is `official-quorum` when official endpoints of two different operators agree, `single-endpoint` when the data came from endpoints of one operator and `custom-endpoints` when it came from endpoints the caller chose, and the result says in words which endpoints were relied upon. An unproven receipt is never reported valid, whatever options are set. While the network pins no roster, no verification returns `valid`, and `unproven` is the honest result.

By default the verifier consults only the official endpoints of the network. Endpoints chosen by the caller are consulted only when `trustCustomEndpoints` is true, or `--trust-custom-endpoints` is passed, and a result reached through them is at best unproven unless a finality proof succeeds. Client objects must name the endpoint they read in their `base` field and are never treated as official. Endpoints count as independent only when they share no resolved address, no host name, no registrable domain and no declared operator. Addresses written in different forms, such as an IPv4 address and its IPv4 mapped IPv6 form or a wildcard name such as one under nip.io that embeds an address, count as the same address, host names are compared in lower case without a trailing dot, and a loopback name counts as both loopback addresses. Official endpoints are grouped in exactly the same way, with their names resolved when the verifier starts, so two official endpoints on one host form one group whatever operator each names. A network that lists one host under two operators is refused, and so is a plan in which two official endpoints of different operators resolve to one address. Caller supplied endpoints that resolve to loopback, private, link local or other special addresses are refused, loopback is allowed only with `allowLoopback` for local development, private addresses only for endpoints on `endpointAllowList`, and when `endpointAllowList` is given no other endpoint is used. The address check is repeated when each connection is opened, and an address that one group of endpoints has resolved to or connected to is refused to every other group, so a name that changes its answer cannot make one host pass for two. The client core that signs and submits a stamp is given this guarded transport as its fetch function, so its requests pass the same checks, and a client core that does not send its requests through that function is refused before any request is made. IPv6 forms that carry an IPv4 address, namely IPv4 mapped and compatible addresses, the well known NAT64 prefix `64:ff9b::/96`, the SIIT prefix `::ffff:0:0/96` and 6to4, are classified by the IPv4 address they carry. The local use NAT64 prefix `64:ff9b:1::/48` can carry an IPv4 address in several layouts, and Teredo `2001::/32` carries one in obscured form, so both are classified as reserved and always refused. Error text sent by an endpoint is never shown, only a short code such as `http 500` or `timeout`. Errors raised by the client core or by an endpoint are replaced by a fixed Qstamp message of at most 200 characters, and the original error is kept only in the `cause` field, which must not be shown to users as it may hold text chosen by an endpoint.

Every https request verifies the certificate of the endpoint and requires TLS 1.2 or later, whatever the environment says, so `NODE_TLS_REJECT_UNAUTHORIZED=0` cannot switch the check off. An organisation whose endpoints use a private certificate authority, or that must present a client certificate, lists such an endpoint as an object `{ url, ca, cert, key }` in `clients` or `rpc`, where each of `ca`, `cert` and `key` is a string or a Buffer in PEM form and `cert` and `key` are given together. An endpoint checked against a certificate authority supplied by the caller is never treated as official, even when its url is an official one. An endpoint listed in a network may carry its own `ca`, `cert` and `key` in that network, and it then stays official.

Each request is cut off when its whole reply has not arrived within 30 seconds, separately from the 20 second limit on an idle connection, and a reply larger than 8 MiB is refused. The functions `verify`, `chainTime`, `stamp` and `complete` accept `deadlineMs`, a limit for the whole operation in milliseconds from 100 to 86400000, and `signal`, an `AbortSignal`. The remaining time is passed down to every request, which is abandoned when the deadline passes or the signal aborts. By default `verify` allows five minutes from the moment it starts to consult endpoints, `chainTime` two minutes, and `stamp` and `complete` two minutes more than their `timeoutMs`. When the limit is reached `verify` returns `indeterminate`, and the other functions reject. Reading a file given to `verify` also stops at the deadline or when the signal aborts. `verify` never throws, and an invalid `deadlineMs` or `signal` gives the status `indeterminate` with the reason in its checks. Each call to `verify`, `chainTime`, `stamp` or `complete` starts its own deadline and signal and never takes those of a call that is already running. Requests that fail for a passing reason are retried with an exponential backoff with random jitter, and an endpoint that answers 429 or 503 with `Retry-After` is not asked again before that time, up to 30 seconds.

When one endpoint reports that the anchor does not match the chain and another reports that it does, or when endpoints that confirm the anchor return different chain data, and no verified finality certificate settles the question, the receipt is reported indeterminate and the endpoints on both sides are named. A receipt is reported invalid only when a check that needs no endpoint fails, when a verified finality certificate refutes the anchor, or when official endpoints of two different operators report that the anchor does not match the chain and no endpoint reports that it does. A denial that only other endpoints report, such as a missing event, a block time that differs or a transaction that is not final, leaves the receipt indeterminate, and so does a withdrawal by the issuer that official endpoints of two operators do not both report. Every result that is not valid carries at least one failing check, and when the result is not invalid every failing check is marked as transport, so a reader of the checks alone never mistakes it for a pass or for a refutation. An endpoint that has not yet reached the height of the anchor is not taken as a denial while its newest block is no later than the anchor time. Block times never decrease, so when that block is already later than the anchor time no block at the anchor height can carry the anchor time, and the endpoint is counted as reporting that the anchor does not match the chain. Several blocks share each whole second, so a newest block with the same time as the anchor is not a denial.

Before any endpoint is trusted, the verifier also rejects an anchor dated before the genesis of the chain and an anchor whose height is higher than the chain can have reached by its time at the fastest block rate allowed for in this release, or lower than the chain had certainly reached at the slowest rate after a stall of one day. The live network produces five blocks a second and the bound allows six. An anchor dated more than five minutes ahead of the clock of the verifier is not refused, since that clock may be slow. Such a receipt is valid only when a verified finality certificate fixes the block at that time, and otherwise it is at best unproven, with a failing `clock` check.

Stamping still accepts chain data only when at least two independent endpoints agree or `trustSingleEndpoint` is true. It may use endpoints chosen by the caller, subject to the same address checks, because every receipt it writes is checked again when it is verified.

The block time is set by the proposing validator in whole seconds. Validators refuse a block whose time is more than 15 seconds ahead of their own clocks or earlier than its parent, so block time never decreases and a receipt time should be read as accurate to within about 15 seconds.

Receipts name the chain by its genesis hash. A receipt verifies only against the chain on which it was created, and a relaunched network with a new genesis cannot be used to verify it, even when it keeps the chain name and the validators keep their keys.

This release is built for the Quantova network `Q-test-net-01`. The native asset of the network is still in its test phase. This release pins no validator roster for that network yet, so no receipt on it verifies as valid and none is proven, and every verification today returns at best `unproven`. A receipt reaches `valid` only once a release pins the validator rosters and checkpoint of the network, and an unproven receipt must not be relied upon as evidence.

## Confidentiality of receipts

A receipt holds the digest of its record and the salt of its leaf. Anyone who holds a receipt can test guesses about the content of a low entropy record, such as a short code or an amount. Receipts should therefore be handled with the same care as the records they describe, and a receipt of a record about a person is personal data. The command line tool writes receipts readable by their owner only. All stamps signed by one account can be linked to each other on the chain, and the record kind is public. An organisation that keeps purposes apart can sign each purpose from its own account with `purposeIndex(label)`, which turns a purpose label into a fixed account index, and fund each account separately.

## Threat model

Qstamp protects the records, the receipts with the digest and salt of each record, the seed of the anchoring account, the pending files that keep salts after an interrupted submission, and the domain ledger of template deployments.

It trusts the genesis hash, contract, official endpoints, validator rosters and checkpoint pinned for each network in `lib/networks.js`, the accounts the verifier names with `expectedSender`, and the storage that holds the seed, receipts and pending files. It does not trust the gateway or any endpoint taken alone, or any party that holds or presents a receipt.

An altered record or receipt fails the digest, the inclusion path or the commitment, and a receipt must hold exactly the expected fields. The commitment binds the genesis hash, the contract, the signer, the kind and the batch size, so it cannot be reused on another chain or contract or claimed by a signer who copies it from a pending transaction. A hostile gateway can delay a result but cannot make a forged receipt valid, because a receipt is valid only through a finality proof checked against the pinned roster, and it cannot make a genuine receipt invalid alone, because a denial by endpoints counts only when official endpoints of two different operators report it. An anchor dated before genesis or at a height the chain cannot have reached by its time is refused before any endpoint is trusted, and `stamp_until` lets the chain refuse an anchor after a deadline. Requests have time and size limits, and only regular files are read.

Qstamp signs no series, so stamping a record twice gives two receipts that each prove only a latest time. `recordDomain` refuses a domain already recorded for a contract. It holds a lock file while it updates the domain ledger, so two processes never both record, and it refuses a ledger that is a link, is not a regular file, belongs to another user or can be written by others, and a ledger folder that other users can change, directly or through a folder above it or an access control list. The ledger is written readable by its owner only. Qstamp cannot revoke a signing account, and withdrawal applies only to the issuer template. When a seed is exposed the integrator moves to a new account and changes `expectedSender`, and earlier receipts keep their time, because a stolen seed cannot anchor in the past. Also left to the integrator are guarding the seed and the receipts, which allow guesses about low entropy records, keeping pending files until their receipts are complete, and confirming that the signer is entitled to the record kind.

## Installation

```
npm install @quantovainc/qstamp
```

Node 20 or later is required. The only runtime dependency is `@quantovainc/qcore`, which provides post quantum transaction signing. The commands below assume the package is installed in the current project. Outside a project, run the tool as `npx @quantovainc/qstamp` so that the scoped package published by Quantova Inc is the one that runs.

## Command line use

Compute fingerprints.

```
qstamp hash report.pdf ledger.csv
```

Stamp one or more files in a single transaction. The key file holds a 32 byte seed as 64 hexadecimal characters and must be readable only by its owner.

```
qstamp stamp report.pdf ledger.csv --seed-file ./signer.key --index 0 --kind financial_record --rpc https://q-test-net-01.quantova.org --rpc https://rpc.example.org
```

Each file receives a receipt named after it with the suffix `.qstamp.json`. Every receipt file is reserved before anything is signed, so a stamp is never paid for without a place to record it. Two inputs that would share one receipt name are refused, and receipts are never written through a symbolic link. Every receipt and pending file is written to a new private file and then moved into place, so an existing receipt replaced with `--force` stays intact until its replacement is complete. The `complete` command writes only files whose names end in `.qstamp.json`, only inside the real folder of the pending file, never through a path that leaves that folder by `..` or a linked folder, and never replaces an existing receipt unless `--force` is given. Without `--out` the files given to `stamp` must lie in one folder, so that their receipts and the pending file share it.

If the transaction is accepted but its outcome cannot be confirmed, the tool keeps a private pending file and names it. The pending file also holds the records and salts when the network fails during submission, so that no stamp is ever lost. The receipts are then recovered with the following command, adding `--tx` with the transaction id when the pending file does not yet name one.

```
qstamp complete qstamp-pending-1760000000000-a1b2c3d4.json
```

Verify a receipt against its record. Verification requires the record or its digest, and it may consult several endpoints.

```
qstamp verify report.pdf.qstamp.json --file report.pdf
```

Draw the deployment domain of an issuer or council template before it is deployed. The value is a random 64 bit number other than zero, drawn from the system source of randomness.

```
qstamp domain
qstamp domain --record domains.json --contract Q1... --genesis <genesis hash> --domain <value>
```

With `--record` the command also writes the domain, the contract address and the genesis hash of the network to the named ledger, and it refuses a domain that the ledger already holds for the same contract address, as well as a second deployment of one contract on one genesis. Without `--domain` it draws a fresh value and records it. The same functions are available as `deploymentDomain()` and `recordDomain(ledger, { contract, genesis, domain })`.

Without `--rpc` the command consults the official endpoints of the network. Endpoints chosen by the operator of the verifier are added with `--rpc` and used only together with `--trust-custom-endpoints`. The option `--expect-sender` names the account that must have signed the anchor and may be given several times. The option `--expect-kind` names the record kind the receipt must carry.

The command exits with status 0 when the receipt is valid, 1 when it is invalid, including a receipt that is not valid JSON or repeats a key, 2 when it could not be evaluated, for example because no endpoint could be reached, and 3 when the receipt matches the chain data reported to it but is unproven. An unproven receipt is printed with a warning that it must not be relied upon as evidence. Usage errors, files that cannot be read and every other failure exit with status 64, so status 1 always means that a receipt was found invalid. Files given to `hash`, `stamp` and `verify --file`, receipts and pending files are read only when they are regular files. Symbolic links, devices and pipes are refused at once rather than read, and a record file may be at most 1 TiB. The same rules apply to `digestFile` and to the `file` option of `verify`. An unreachable endpoint never produces a valid result. Unknown or misspelt options are refused before any action is taken. Text received from an endpoint is stripped of control characters before it is shown, and an endpoint listed twice is consulted once.

## Programmatic use

```js
const qstamp = require('@quantovainc/qstamp');

const digest = await qstamp.digestFile('report.pdf');
const clients = ['https://q-test-net-01.quantova.org', 'https://rpc.example.org'];
const [receipt] = await qstamp.stamp({
  seed,
  index: 0,
  kind: 'financial_record',
  records: [{ digest }],
  clients,
});

const result = await qstamp.verify(receipt, { file: 'report.pdf' });
if (!qstamp.isProven(result)) {
  throw new Error('the receipt is not proven, status ' + result.status);
}
```

Regulated users must require `isProven(result)` before relying on a receipt. It is true only for the status `valid` reached through a finality proof.

While a stamp is in progress, a second stamp from the same account on the same chain in the same process waits until the first has finished, so that two stamps never read the same account nonce. A stamp that cannot obtain its turn before its deadline fails without sending anything, and it never gives up the turn of a stamp ahead of it.

The seed must be supplied as a `Uint8Array` of 32 bytes so that the caller can wipe it. Text seeds are refused because text cannot be erased from memory. The SDK signs from a private copy and overwrites that copy with zeros as soon as the transaction is signed. The underlying signing library also holds the seed briefly in its own memory, which cannot be wiped from JavaScript.

The function chainTime returns the time of the finalised chain head read from the same endpoints. It takes the latest reading, refuses an endpoint whose head is more than 30 seconds behind or ahead of the local clock or behind a chain time seen earlier in the process through the same set of endpoints, and refuses endpoints that disagree by more than that margin, so neither a wrong local clock nor a single endpoint can move a decision about expiry into the past. Earlier chain times are remembered for each set of endpoints, where each endpoint is identified by its normalised address or lower case host name and its port, so writing a url with a trailing slash, in upper case or with another form of its address does not give a set a fresh record. The records of sets made only of official endpoints are always kept. The records of the 1024 most recently used other sets are kept as well, so a caller that reads many other sets in the same process can push out the record of a set it does not use, which then accepts any chain time within the margin again. Reading one set, including the endpoints a stamp with a deadline reads, never changes the record of another set. The margin can be changed with `clockSlackMs`. Endpoints chosen by the caller are used only with `trustCustomEndpoints`, and the result states in `trust` and `officialEndpoints` what it relied upon.

The `verify` result reports a status of valid, invalid, indeterminate or unproven, the trust value and a sentence in `trustDetail` that says what was relied upon, whether the result is `proven`, whether every endpoint consulted was an official one in `officialEndpoints`, the operators consulted, whether an expected issuer and an expected kind were checked in `senderChecked` and `kindChecked`, any notices, and every check with its outcome and reason. A receipt is never reported valid unless the record or its digest was supplied and matched and the anchor was proven.

Every error raised after the transaction is accepted carries the pending batch in a plain form that can be stored. An error raised while the network was being contacted to submit the transaction carries the pending batch as well, with the code `QSTAMP_UNCONFIRMED` and no transaction id, so that its salts are never lost. `complete` finishes the receipts from that pending batch once the transaction is final. The `onPending` option receives the pending batch before the SDK waits for finality, so that an application can store it first. It must finish within the deadline of the stamp, otherwise the stamp is rejected with the pending batch attached and the account is released for the next stamp. `onPending` and the methods of client objects run outside the deadline and signal of the stamp, so work they start later is not cut off by a stamp that has already finished.

Receipts produced by an institution through its own deployment of a Qstamp contract template are verified by passing that contract address together with `trustCustomContract` set to true. Without that flag the verifier accepts only the official contract of each network. For such contracts the verifier also reads the withdrawal state of the issuer template, and a commitment the issuer has withdrawn is reported invalid with its reason code in `revoked`. When the withdrawal state cannot be read, or an endpoint leaves out the withdrawal slot of the commitment, the result is never valid. Only the issuer template keeps a withdrawal map. For a stamp recorded by the council template, or by any contract that emits the event of the open contract, withdrawal does not apply, no withdrawal state is read and `revoked` is null.

The record kind is chosen by whoever signs the anchor and is not checked by the open contract. A verifier must therefore confirm that the anchor was signed by an account entitled to issue records of that kind, either by passing `expectedSender` with that account or by checking `anchor.sender` in the receipt itself, and it should pass `expectedKind` with the kind it expects. Without `expectedSender` a valid result shows only that the account named in the receipt stamped the record, and the result reports this with `senderChecked` false and a notice.

## Record kinds

The kind is an unsigned 64 bit value recorded on the chain with each commitment. Named kinds are record 0, file 1, document 2, software release 3, AI model 4, AI dataset 5, AI agent action 6, AI output 7, wallet binding 8, financial record 9 and public record 10, where public record refers to records held by public bodies and does not mean that the record is published. Other values are available for private schemes.

## Independent verification procedure

An auditor can verify a receipt without this SDK by following these steps.

1. Compute the digest of the record with the algorithm named in the receipt and compare it with the receipt digest.
2. Compute the leaf from the byte 0x00, the label QSTAMP/LEAF/V1, the algorithm identifier (1 for SHA3 with a 256 bit output and 2 for SHA2 with a 256 bit output), the digest and the salt.
3. Recompute the tree root from the leaf, the position, the batch size and the inclusion path using the procedure of RFC 9162 section 2.1.3.2, and compare it with the receipt root.
4. Compute the commitment from the byte 0x02, the label QSTAMP/ROOT/V1, the genesis hash, the contract address bytes, the signer address bytes, the kind, the batch size and the root.
5. Confirm that the anchor time is not before the genesis of the chain and not in the future, and that the height is consistent with the time.
6. Obtain the header of the block at that height with its finality certificate, check the certificate against the validator roster of its epoch, and confirm that validators holding more than two thirds of the stake signed it and that the header time equals the receipt time.
7. Obtain the inclusion proof of the stamp event under the event root of that header and confirm that the event is the one emitted by the official contract with selector 5a110849, whose data is the signer address, the commitment and the kind.
8. Obtain the inclusion proof of the anchoring transaction under the transaction root of that header, confirm that the SHA3 hash of the transaction bytes written as a QTX identifier is the transaction id in the receipt, and confirm that the transaction is a contract call signed by the stated address, sent to the official contract and carrying the commitment and kind.
9. Where no finality certificate can be checked, query endpoints run by at least two different operators for the anchoring transaction, the events at that height and the block, and confirm that they agree, that the transaction is final, was signed by the stated address, was sent to the official contract and carries the commitment and kind, and that the block identifier and time match.
10. Confirm that the signer address is entitled to issue records of the stated kind.

## Network

The Quantova test network is identified by the chain name `Q-test-net-01`, whose numeric chain id, the first eight bytes of the SHA3 hash of the name read big endian, is 6995079887857407393. The public endpoint is `https://q-test-net-01.quantova.org`, operated by Quantova Inc. The network is being relaunched under this name, and the genesis hash `5f18d6fbd39e55152cbb3f7986d50cc52e436fe577d5a47307e092a761f6a4c9`, the genesis time and the contract `Q1PVRQ8DQ6YYUEDH68QEM3PWT6JC9U9TP95V2QHU2PFDF2ZVNH5NQQRNM92J` held in `lib/networks.js` are those of the network before the relaunch. They stay in place only until the relaunched network publishes its own genesis and contract, they do not describe a live network, and a receipt made on the relaunched network verifies only with a release that pins its genesis.

Each network in `lib/networks.js` lists its official endpoints in `rpcs`, each with the url and the name of the operator that runs it. A second endpoint run by an independent operator is added as a further entry in that list, and verification then reaches the status valid through an official quorum. The validator rosters used for finality proofs are pinned per epoch in the `finality.rosters` entry of the same file, which is empty until a roster is published. `finality.genesis` names the genesis those rosters belong to and must equal the genesis of the network, and `finality.checkpoint` may give the height and header hash of a certified block of that chain. Each validator in a pinned roster names its `id`, `stake`, `attest_pk`, `root` and `root_slots` exactly as `get_validator_set` serves them, and a roster that leaves out the sortition root or its slot count is refused. `finality.epochBlocks` fixes the epoch length once it is final. Once a roster is pinned the network accepts an anchor only through a finality proof.

An SDK built on Qstamp may verify against a sovereign or private network that it describes as a network object of the same shape. Qstamp checks every such object before it is used and refuses one that is incomplete.

1. `name`, `chainId`, `genesis` and `contract` identify the chain and its stamp contract.
2. `genesisTime` and `blocks` are required. `blocks` gives `minPerSecond`, `maxPerSecond`, `stallSeconds` and `slack`, and the anchor height of every receipt is checked against them before any endpoint is trusted. They should allow the real block rate of the network with a small margin and no more.
3. `rpcs` lists from one to eight endpoints, each with its `url` and `operator`, and optionally `ca`, `cert` and `key` in PEM form for a private certificate authority or a client certificate. One host may not appear under two operators.
4. An endpoint reached over plain http is refused unless it is a loopback address and the caller sets `allowLoopback`, or the entry carries `insecure` set to true. `insecure` is meant only for an air gapped network whose links cannot be reached by anyone else, because plain http lets anyone on the path answer for the endpoint. Such a network should pin its validator rosters so that only a finality proof is accepted.
5. `finality` gives `genesis`, `checkpoint`, `epochBlocks` and `rosters` as for the built in networks, where a missing `genesis` stands for the genesis of the network and a `checkpoint` is required whenever a roster is pinned, and `requireFinality` sets whether an anchor is accepted only through a finality proof. It defaults to true when rosters are pinned and to false otherwise.

## Contract

The source of the open contract is `contract/QStamp.qs`, and the package ships the container compiled from it as `contract/QStamp.qbc` together with its SHA256 hash in `contract/QStamp.qbc.sha256` and the interface the compiler emits for it in `contract/QStamp.interface.json`. The compiler lays out the arguments of each entry in their declared order, and the SDK reads the selector, offset and width of every argument from that interface rather than from fixed numbers. The interfaces of the issuer and council templates are shipped in `contract/templates` and are used in the same way to locate the commitment in calls to those contracts. Running `bash scripts/build-contract.sh` builds the Quanta compiler at commit `071324a83f49aba0c638b61446f87b661a1008b1`, compiles the source without a provenance key and confirms that the container and its interface equal the shipped files byte for byte. With `QSTAMP_TEMPLATES_DIR` set to a checkout of the Qstamp templates, it also confirms the template interfaces. A container deployed on chain is the canonical container followed by the provenance signature of the attested compiler, so a deployment is tied to this source by comparing its canonical part with `contract/QStamp.qbc`.

## Licence

Qstamp is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files `LICENSE-APACHE` and `LICENSE-MIT`, and the notice is in `NOTICE`.
