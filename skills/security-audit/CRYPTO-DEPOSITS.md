# Crypto Deposit Crediting Hunting

#### When to use this file

Reach for this file only when the target credits something of value from an observed blockchain transfer: an exchange or wallet deposit, a payment gateway or invoice marked paid, an order released after payment, a bridge or custody inbound flow, a game or casino top-up, or a bot that confirms payment from an explorer link. The important data flow is *chain data (node RPC, indexer, explorer API, webhook, user-supplied tx hash) → deposit parser → balance, order, or payment status*.

**Detection gate.** Reconnaissance decides this from source, not from dependency names. The flow exists when source contains all of:

1. a reader of chain data: node RPC calls such as `getTransaction`, `eth_getTransactionReceipt`, `eth_getLogs`, `gettransaction`, `account_tx`, `getTransactionsByAddress`, a chain SDK, an indexer or explorer API client, or a chain webhook handler; and
2. a write that credits a principal or releases goods: a balance, ledger, order, invoice, or payment-status update driven by that data.

If the gate is not met, skip this file: record each block in `excluded_blocks` with the reason `no source-visible crypto deposit crediting path` and do not seed units for it. If the gate is met, selecting this file is mandatory for every crediting path found, and every attack class below is selected unless a source fact (for example, the target supports only one chain) excludes it; record that fact as the exclusion reason.

Use this alongside `ATTACK-CLASSES.md`. Webhook authenticity, API authorization, and queue handling stay in their ordinary blocks and in `PROTOCOLS-RPC-AND-MESSAGING.md`. This file covers how the target decides that a real deposit of a specific asset and amount reached a specific user.

## Core discipline (include in every agent prompt for this domain)

```
- A fake deposit is a transaction that the chain accepts but that does not move the credited asset, amount, or recipient the target believes it does. The finding is the code path that credits it, not the existence of fake tokens on a public chain.
- Name the depositor, the credited principal, the asset identity the code trusts, the amount source, the status check, and the finality rule. Each of these is a separate control.
- Asset identity is the canonical on-chain identifier from a source-visible allowlist: EVM or TRON contract address, Solana mint, TON jetton master plus derived jetton wallet, XRP Ledger issuer plus currency, EOS contract account, Omni property id. Symbol, name, decimals, logo, and explorer labels are attacker-controlled.
- The credited amount is what the chain recorded as delivered to the target-owned account, not the amount field the sender requested.
- Inclusion is not success. A transaction in a block can be failed, aborted, bounced, partially applied, or later replaced.
- Explorer labels and third-party summaries are derived views. Count only checks the target performs against node data or a source-visible verified indexer contract.
- Use dummy fixtures: recorded transaction JSON, a local devnet, or a mocked RPC response. Never send transactions to a public network or a shared node.
```

## Asset identity attack classes (subagent_type: `general`)

**Asset identified by symbol or metadata**
The parser credits a token because its symbol, name, decimals, or metadata says USDT, or because a lookup table is keyed by symbol. Anyone can deploy a token with identical metadata on every major chain. Find where the asset is resolved and check that the decision compares the canonical identifier against an allowlist per chain and network (mainnet versus testnet ids differ). Check also that native-coin paths cannot be reached with a token that claims the native symbol, for example an EOS token issued by a contract other than `eosio.token`.

**Asset resolved from the wrong account or the wrong moment**
The parser derives the asset from the source account, from a field the sender controls, or from state after the transaction instead of the destination account's state for the instruction that moved value. Solana case: an SPL `transfer` (not `transferChecked`) carries no mint; an attacker transfers a fake token from a keypair token account, then closes and re-creates that same address as a canonical-mint account in the same transaction, so `postTokenBalances` and explorers show the canonical asset as the source mint. Check that the credited mint comes from the destination token account and that the amount comes from the destination's pre/post balance delta for the canonical mint and the deposit owner.

**Jetton or token wallet not bound to its master**
On TON each holder has a separate jetton wallet contract. A `transfer_notification` can come from any contract and carries attacker-chosen amount and payload. Check that the sender of the notification equals `get_wallet_address(deposit_owner)` on the allowlisted jetton master, computed or queried by the target, and that the jetton wallet's own balance actually increased.

## Execution status attack classes (subagent_type: `general`)

**Included but failed or aborted transaction credited**
The parser reads a transaction or its logs without checking execution success. Check each chain-specific field the target relies on: EVM `receipt.status == 1`; TRON `ret[0].contractRet == "SUCCESS"` and `receipt.result == "SUCCESS"` from transaction info; Solana `meta.err == null`; EOS `status == "executed"` (not `hard_fail`, `soft_fail`, or `delayed`); TON compute and action phases successful and `aborted == false`; Omni `valid == true`; XRP Ledger `meta.TransactionResult == "tesSUCCESS"`.

**Token call that returns false without reverting**
Some ERC-20 and TRC-20 contracts return `false` on insufficient balance instead of reverting, so the outer transaction succeeds without moving tokens. Check that crediting depends on a canonical `Transfer` log from the allowlisted contract or on a balance delta, never on transaction success plus decoded call data.

**Failed internal call inside a successful transaction**
Native value forwarded through a contract call, a multicall, or a TON internal message can fail while the outer transaction succeeds. Check that internal-transfer crediting uses execution traces and skips frames with an error or revert, and that TON deposits are credited from the destination account's transaction, not from the outgoing message on the sender side.

**Bounced message credited**
On TON a message with the bounce flag that fails on the destination returns its value to the sender in a bounced message. A parser that credits on seeing an inbound message, or that counts both the inbound and the bounce, credits value that never stayed. Check that the destination transaction succeeded, that no bounce was generated from it, and that bounced inbound messages are never credited.

## Amount semantics attack classes (subagent_type: `general`)

**Requested amount credited instead of delivered amount**
XRP Ledger `Payment` with the `tfPartialPayment` flag carries a large `Amount` while only `meta.delivered_amount` arrives. Fee-on-transfer, rebasing, and Token-2022 transfer-fee tokens deliver less than the instruction amount. Check that the credited amount is the delivered field or the recipient-side balance delta, and that the code rejects or handles the partial-payment flag explicitly.

**Decimals and unit conversion**
The parser scales by decimals from metadata the token controls, by a constant for a different chain's version of the asset, or with floating-point arithmetic. Check that decimals come from the allowlist entry for that exact asset identity and that conversion is integer-exact.

## Event and recipient binding attack classes (subagent_type: `general`)

**Forged or foreign event logs**
Any contract can emit an event with the `Transfer` signature and arbitrary fields. Check that each credited EVM or TRON log has `log.address` equal to the allowlisted token contract, the expected number of indexed topics, and a `to` field equal to a deposit address. On Solana, check that parsed transfer instructions come from the real Token or Token-2022 program id, including inner instructions invoked by other programs.

**Credited to the wrong principal**
The parser maps the transfer to a user by a field the attacker controls or by a deposit address that is not exclusively owned. Check the binding for each chain the target supports: EVM and TRON `to` address; Solana destination token account whose `owner` is the deposit wallet (the account need not be the ATA, so check owner and mint, not address shape); XRP Ledger destination tag, TON text comment, and EOS memo with a defined rule for a missing, malformed, or reused tag. Check that a transfer between two target-owned addresses (sweeps, change outputs) does not credit a user.

## Finality and replay attack classes (subagent_type: `general`)

**Credit before finality**
The target credits at `processed` or `confirmed` commitment, at zero or too few confirmations, or on a mempool event. Bitcoin RBF and EVM or Bitcoin reorgs can remove or replace the transaction. Check the confirmation rule per chain, that credit is reversed or withheld if the transaction leaves the canonical chain, and that withdrawals cannot spend unfinal credit.

**Double credit of one transfer**
The same transfer is credited twice through retries, rescans, a webhook replay, two indexers, a reorg re-inclusion, or because the dedup key is too coarse or too fine. Check that the unique key identifies the transfer, not only the transaction: EVM or TRON hash plus log index, Solana signature plus instruction index (outer and inner), TON transaction hash plus logical time, Bitcoin txid plus output index. Check that the key is enforced by a unique constraint or an atomic write, not a read-then-write.

## Data source trust attack classes (subagent_type: `general`)

**Explorer, indexer, or user-supplied evidence trusted**
The target accepts an explorer URL, screenshot, or user-supplied transaction hash, or reads a third-party explorer API, and credits from its summary fields such as token symbol, `amount`, or `status`. Check that the target re-fetches the transaction from a node or verified indexer it controls, applies every check above, and binds the transaction to the expected invoice or user so one real deposit cannot satisfy several claims.

## Universal moves (apply across the above)

- Build a table per supported chain and asset: canonical identifier, status field checked, amount source, recipient binding, finality rule, and dedup key. An empty cell is a lead.
- Start at the write that credits a balance or releases goods and trace backward to the raw node response. Every field used in the decision must come from that response, not from a cache, explorer label, or sender-controlled payload.
- Compare paths for the same deposit: native versus token, outer versus inner instruction or internal call, webhook versus polling, first credit versus rescan, single versus batched transfers.
- Replay recorded fixtures of known fake-deposit shapes through the parser locally: failed transaction, fake token with the canonical symbol, forged log from a foreign contract, partial payment, bounced message, Solana close-and-reinit source account, duplicate delivery.

## Validation rules (apply before reporting ANY finding here)

1. Name the crediting write, the depositor, the credited principal, and the asset, amount, or status that differs from what the chain delivered.
2. Prove reachability with a source trace from the chain-data reader to the crediting write. A missing check with no path to a credit is not a finding.
3. Prefer a local replay: feed a recorded or synthetic transaction fixture into the parser or a local devnet and observe the wrong credit on a dummy account. Do not broadcast transactions to a public or shared network.
4. Mark `needs_validation` when the decision depends on a node, indexer, or explorer behavior that is not visible in source or fixtures, and state the exact field and the owner-observable check that resolves it.
5. Severity follows the credited value: a credit that can be withdrawn or exchanged for real assets defeats the deposit control fully.
