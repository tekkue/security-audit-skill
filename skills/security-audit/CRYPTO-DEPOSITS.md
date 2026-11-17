# Crypto Deposit Crediting Hunting

#### When to use this file

Reach for this file only when the target credits something of value from an observed blockchain transfer: an exchange or wallet deposit, a payment gateway or invoice marked paid, an order released after payment, a bridge or custody inbound flow, a game or casino top-up, or a bot that confirms payment from an explorer link. The important data flow is *chain data (node RPC, indexer, explorer API, webhook, user-supplied tx hash) → deposit parser → balance, order, or payment status*.

**Detection gate.** Reconnaissance decides this from source, not from dependency names. The flow exists when source contains all of:

1. a reader of chain data: node RPC calls such as `getTransaction`, `eth_getTransactionReceipt`, `eth_getLogs`, `gettransaction`, `account_tx`, `getTransactionsByAddress`, `/cosmos/tx/v1beta1/txs`, `sui_getTransactionBlock`, `EXPERIMENTAL_tx_status`, `get_transfers`, a chain SDK, an indexer or explorer API client, or a chain webhook handler; and
2. a write that credits a principal or releases goods: a balance, ledger, order, invoice, or payment-status update driven by that data.

If the gate is not met, skip this file: record each block in `excluded_blocks` with the reason `no source-visible crypto deposit crediting path` and do not seed units for it. If the gate is met, selecting this file is mandatory for every crediting path found, and every attack class below is selected unless a source fact (for example, the target supports only one chain) excludes it; record that fact as the exclusion reason.

Use this alongside `ATTACK-CLASSES.md`. Webhook authenticity, API authorization, and queue handling stay in their ordinary blocks and in `PROTOCOLS-RPC-AND-MESSAGING.md`. This file covers how the target decides that a real deposit of a specific asset and amount reached a specific user.

## Core discipline (include in every agent prompt for this domain)

```
- A fake deposit is a transaction that the chain accepts but that does not move the credited asset, amount, or recipient the target believes it does. The finding is the code path that credits it, not the existence of fake tokens on a public chain.
- Name the depositor, the credited principal, the asset identity the code trusts, the amount source, the status check, and the finality rule. Each of these is a separate control.
- Asset identity is the canonical on-chain identifier from a source-visible allowlist: EVM or TRON TRC-20 contract address, TRON TRC-10 token id, Solana mint, TON jetton master plus derived jetton wallet, XRP Ledger issuer plus currency, Stellar asset code plus issuer, EOS contract account, Omni property id, Cosmos full denom with its IBC trace, Cardano policy id plus asset name, Aptos or Sui full type tag including the package address (or fungible asset metadata object), Algorand ASA id, Substrate pallet plus asset id. Symbol, name, decimals, logo, and explorer labels are attacker-controlled.
- The credited amount is what the chain recorded as delivered to the target-owned account, not the amount field the sender requested.
- Inclusion is not success. A transaction in a block can be failed, aborted, bounced, refunded, partially applied, script-invalid, or later replaced.
- Explorer labels and third-party summaries are derived views. Count only checks the target performs against node data or a source-visible verified indexer contract.
- Use dummy fixtures: recorded transaction JSON, a local devnet, or a mocked RPC response. Never send transactions to a public network or a shared node.
```

## Asset identity attack classes (subagent_type: `general`)

**Asset identified by symbol or metadata**
The parser credits a token because its symbol, name, decimals, or metadata says USDT, or because a lookup table is keyed by symbol or by a short name. Anyone can deploy a token with identical metadata on every major chain. Find where the asset is resolved and check that the decision compares the full canonical identifier against an allowlist per chain and network (mainnet versus testnet ids differ). Typical gaps: Move type tags compared by module and struct name without the package address, Cardano assets matched by asset name without policy id, TRON TRC-10 matched by name instead of token id, Stellar assets matched by code without issuer. Check also that native-coin paths cannot be reached with a token that claims the native symbol, for example an EOS token issued by a contract other than `eosio.token`.

**Bridged or IBC asset accepted by base denom**
A wrapped, bridged, or IBC voucher is accepted because its base denom or underlying symbol matches, while its route differs. On Cosmos chains any counterparty connected through any channel can create an `ibc/<hash>` voucher whose trace ends in `uatom` or `uusdc`. Check that the target resolves the full denom trace and accepts only the allowlisted port, channel, and client for each asset, and that the same rule applies to bridge-wrapped tokens on other chains (allowlisted bridge contract, not underlying symbol).

**Asset resolved from the wrong account or the wrong moment**
The parser derives the asset from the source account, from a field the sender controls, or from state after the transaction instead of the destination account's state for the instruction that moved value. Solana case: an SPL `transfer` (not `transferChecked`) carries no mint; an attacker transfers a fake token from a keypair token account, then closes and re-creates that same address as a canonical-mint account in the same transaction, so `postTokenBalances` and explorers show the canonical asset as the source mint. Check that the credited mint comes from the destination token account and that the amount comes from the destination's pre/post balance delta for the canonical mint and the deposit owner.

**Jetton or token wallet not bound to its master**
On TON each holder has a separate jetton wallet contract. A `transfer_notification` can come from any contract and carries attacker-chosen amount and payload. Check that the sender of the notification equals `get_wallet_address(deposit_owner)` on the allowlisted jetton master, computed or queried by the target, and that the jetton wallet's own balance actually increased.

## Execution status attack classes (subagent_type: `general`)

**Included but failed or aborted transaction credited**
The parser reads a transaction or its logs without checking execution success. Check each chain-specific field the target relies on: EVM `receipt.status == 1`; TRON `ret[0].contractRet == "SUCCESS"` and `receipt.result == "SUCCESS"` from transaction info; Solana `meta.err == null`; EOS `status == "executed"` (not `hard_fail`, `soft_fail`, or `delayed`); TON compute and action phases successful and `aborted == false`; Omni `valid == true`; XRP Ledger `meta.TransactionResult == "tesSUCCESS"`; Stellar `successful == true`; Cosmos `code == 0`; Sui `effects.status == "success"`; Aptos `success == true`; Substrate no `System.ExtrinsicFailed` event for that extrinsic; NEAR every receipt in the outcome tree ends in success. Cardano case: a transaction that fails phase-2 script validation is still in a block with `isValid == false`; its body outputs are never created and only collateral moves, so a parser that reads body outputs credits value that does not exist.

**Token call that returns false without reverting**
Some ERC-20 and TRC-20 contracts return `false` on insufficient balance instead of reverting, so the outer transaction succeeds without moving tokens. Check that crediting depends on a canonical `Transfer` log from the allowlisted contract or on a balance delta, never on transaction success plus decoded call data.

**Failed internal call inside a successful transaction**
Native value forwarded through a contract call, a multicall, a TON internal message, an Algorand inner transaction, or a NEAR cross-contract receipt can fail while the outer transaction succeeds. Check that internal-transfer crediting uses execution traces or per-receipt outcomes, skips frames with an error or revert, and credits TON deposits from the destination account's transaction, not from the outgoing message on the sender side.

**Bounced message credited**
On TON a message with the bounce flag that fails on the destination returns its value to the sender in a bounced message. A parser that credits on seeing an inbound message, or that counts both the inbound and the bounce, credits value that never stayed. Check that the destination transaction succeeded, that no bounce was generated from it, and that bounced inbound messages are never credited.

**Asynchronous refund after a logged transfer**
On NEAR, `ft_transfer_call` logs a transfer to the receiver, then calls the receiver's `ft_on_transfer`; whatever amount that call returns as unused, or the full amount if it fails, is refunded to the sender in `ft_resolve_transfer`. A parser that credits from the first transfer log credits tokens that were returned. Check that the credited amount is net of the resolve step, or comes from the receiver's balance change after all receipts finish, and that the target's own `ft_on_transfer` return value matches what it credited.

## Amount semantics attack classes (subagent_type: `general`)

**Requested amount credited instead of delivered amount**
XRP Ledger `Payment` with the `tfPartialPayment` flag carries a large `Amount` while only `meta.delivered_amount` arrives. Stellar path payments deliver the amount in the operation result, not the send-side amount. Fee-on-transfer, rebasing, and Token-2022 transfer-fee tokens deliver less than the instruction amount. Check that the credited amount is the delivered field or the recipient-side balance delta, and that the code rejects or handles the partial-payment flag explicitly.

**Decimals and unit conversion**
The parser scales by decimals from metadata the token controls, by a constant for a different chain's version of the asset, or with floating-point arithmetic. Check that decimals come from the allowlist entry for that exact asset identity and that conversion is integer-exact.

## Event and recipient binding attack classes (subagent_type: `general`)

**Forged or foreign event logs**
Any contract can emit an event that looks like a transfer. Check that each credited EVM or TRON log has `log.address` equal to the allowlisted token contract, the expected number of indexed topics, and a `to` field equal to a deposit address. On Solana, check that parsed transfer instructions come from the real Token or Token-2022 program id, including inner instructions invoked by other programs. On Aptos and Sui, check that the event type's package address is the framework or the allowlisted token package, or credit from balance changes instead of events. On Cosmos, check that transfer attributes come from the bank module's `transfer` or `coin_received` events, not from a CosmWasm `wasm-*` event with the same attribute keys. On Substrate, check the emitting pallet and that the event belongs to the credited extrinsic.

**Credited to the wrong principal**
The parser maps the transfer to a user by a field the attacker controls or by a deposit address that is not exclusively owned. Check the binding for each chain the target supports: EVM and TRON `to` address; Solana destination token account whose `owner` is the deposit wallet (the account need not be the ATA, so check owner and mint, not address shape); XRP Ledger destination tag, Stellar memo, Cosmos memo, TON text comment, and EOS memo with a defined rule for a missing, malformed, or reused tag. Check that a transfer between two target-owned addresses (sweeps, change outputs) does not credit a user.

**Value parked for the recipient but not in its balance**
Some operations name the deposit address without increasing its spendable balance: Stellar `create_claimable_balance` and escrow or vesting outputs on several chains. A parser that credits on the recipient field credits value the target cannot spend or that the sender can reclaim. Check that the credit follows a balance increase the target controls, or the target's own claim of the parked value.

## Finality and replay attack classes (subagent_type: `general`)

**Credit before finality**
The target credits at `processed` or `confirmed` commitment, at zero or too few confirmations, or on a mempool event. Bitcoin RBF and reorgs on probabilistic-finality chains (Bitcoin family, Cardano, Monero, proof-of-work EVM chains) can remove or replace the transaction. Check the confirmation rule per chain, that credit is reversed or withheld if the transaction leaves the canonical chain, and that withdrawals cannot spend unfinal credit.

**Double credit of one transfer**
The same transfer is credited twice through retries, rescans, a webhook replay, two indexers, a reorg re-inclusion, or because the dedup key is too coarse or too fine. Check that the unique key identifies the transfer, not only the transaction: EVM or TRON hash plus log index, Solana signature plus instruction index (outer and inner), TON transaction hash plus logical time, Bitcoin or Cardano txid plus output index, Cosmos tx hash plus message and event index, Substrate block plus extrinsic and event index, NEAR receipt id, Stellar operation id. Check that the key is enforced by a unique constraint or an atomic write, not a read-then-write.

**Outputs that share a one-time key**
On Monero an attacker can send several outputs to the same one-time public key; the wallet sees each output, but all of them share one key image, so only one can ever be spent. The 2018 "burning bug" let a depositor get credit for every output while the exchange could spend one. Check that the wallet code or RPC version used marks duplicate one-time keys as unspendable and that crediting counts only outputs with a unique one-time key, keeping the largest amount.

**Credit revocable by the issuer**
An accepted asset whose issuer can claw back or freeze balances after credit: Algorand ASA clawback and freeze addresses, Stellar clawback and authorization-revocable flags, admin freeze or blacklist functions on EVM and TRON tokens. For allowlisted stablecoins this is an accepted business risk. For any other asset, check that the allowlist entry records the issuer controls and that the target does not accept user-chosen assets with an active clawback authority.

## Data source trust attack classes (subagent_type: `general`)

**Explorer, indexer, or user-supplied evidence trusted**
The target accepts an explorer URL, screenshot, or user-supplied transaction hash, or reads a third-party explorer API, and credits from its summary fields such as token symbol, `amount`, or `status`. Check that the target re-fetches the transaction from a node or verified indexer it controls, applies every check above, and binds the transaction to the expected invoice or user so one real deposit cannot satisfy several claims.

**Indexer-defined assets**
On Bitcoin, BRC-20 and Runes balances exist only under an indexer's rules, not in consensus. A transfer inscription that is invalid under those rules, a Runes cenotaph that burns the runes, or a disagreement between indexer versions produces a transaction that looks like a deposit. Check that the target pins one indexer implementation and version, reads the indexer's validity result for the exact transfer, and waits for that indexer to process the confirmed block before crediting.

## Universal moves (apply across the above)

- Build a table per supported chain and asset: canonical identifier, status field checked, amount source, recipient binding, finality rule, and dedup key. An empty cell is a lead.
- Start at the write that credits a balance or releases goods and trace backward to the raw node response. Every field used in the decision must come from that response, not from a cache, explorer label, or sender-controlled payload.
- Compare paths for the same deposit: native versus token, outer versus inner instruction or internal call, webhook versus polling, first credit versus rescan, single versus batched transfers.
- Replay recorded fixtures of known fake-deposit shapes through the parser locally: failed transaction, fake token with the canonical symbol, forged log or event from a foreign contract or module, partial payment, bounced message, NEAR refunded `ft_transfer_call`, Cardano `isValid == false`, IBC voucher from an unlisted channel, Solana close-and-reinit source account, duplicate delivery.

## Validation rules (apply before reporting ANY finding here)

1. Name the crediting write, the depositor, the credited principal, and the asset, amount, or status that differs from what the chain delivered.
2. Prove reachability with a source trace from the chain-data reader to the crediting write. A missing check with no path to a credit is not a finding.
3. Prefer a local replay: feed a recorded or synthetic transaction fixture into the parser or a local devnet and observe the wrong credit on a dummy account. Do not broadcast transactions to a public or shared network.
4. Mark `needs_validation` when the decision depends on a node, indexer, or explorer behavior that is not visible in source or fixtures, and state the exact field and the owner-observable check that resolves it.
5. Severity follows the credited value: a credit that can be withdrawn or exchanged for real assets defeats the deposit control fully.
