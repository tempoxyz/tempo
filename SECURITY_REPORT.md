# Laporan Keamanan: Celah Bypass Compliance di Jalur Subblock RPC

## Ringkasan Eksekutif

Ditemukan potensi celah keamanan di mana transaksi yang dikirim melalui jalur Subblock RPC dapat melewati pemeriksaan kepatuhan (Compliance) dan QoS (Payment Lanes), khususnya validasi TIP-403 Policy Registry untuk fee payer yang masuk blacklist.

## Detail Temuan

### Lokasi Celah

1. **File**: `crates/node/src/rpc/mod.rs`
   - **Baris**: 328-340
   - **Fungsi**: `send_transaction` dalam implementasi `EthTransactions` untuk `TempoEthApi`
   - **Masalah**: Transaksi dengan `subblock_proposer()` diarahkan langsung ke subblocks service tanpa melalui transaction pool validator

2. **File**: `crates/commonware-node/src/subblocks.rs`
   - **Baris**: 227-239 (`on_new_subblock_transaction`)
   - **Masalah**: Transaksi hanya disimpan dalam map tanpa validasi
   - **Baris**: 680-746 (`build_subblock`)
   - **Masalah**: Menggunakan `evm.transact_commit()` langsung tanpa memanggil validator
   - **Baris**: 756-821 (`validate_subblock`)
   - **Masalah**: Hanya melakukan validasi eksekusi EVM, tidak memanggil `validate_transaction` dari transaction pool validator

### Validasi yang Dilewati

Transaksi melalui jalur subblock melewati validasi berikut yang seharusnya dilakukan oleh `TempoTransactionValidator`:

1. **TIP-403 Policy Registry Blacklist Check untuk Fee Payer**
   - **File**: `crates/transaction-pool/src/validator.rs`, baris 293-310
   - **Fungsi**: `can_fee_payer_transfer`
   - **Implementasi**: `crates/revm/src/common.rs`, baris 247-266
   - **Dampak**: Fee payer yang masuk blacklist dapat tetap mengeksekusi transaksi

2. **Validasi Balance Fee Token**
   - **File**: `crates/transaction-pool/src/validator.rs`, baris 312-333
   - **Dampak**: Transaksi dengan balance tidak cukup dapat tetap dieksekusi

3. **Validasi Fee Token Validity**
   - **File**: `crates/transaction-pool/src/validator.rs`, baris 276-290
   - **Dampak**: Fee token yang tidak valid dapat digunakan

4. **Validasi AMM Liquidity**
   - **File**: `crates/transaction-pool/src/validator.rs`, baris 335-351
   - **Dampak**: Transaksi dengan liquidity tidak cukup dapat tetap dieksekusi

5. **Validasi Keychain Authorization**
   - **File**: `crates/transaction-pool/src/validator.rs`, baris 71-167
   - **Dampak**: Keychain operations yang tidak valid dapat dilewati

### Alur Transaksi Normal vs Subblock

#### Alur Normal (Aman)
```
RPC send_transaction
  ↓
Transaction Pool
  ↓
TempoTransactionValidator.validate_transaction()
  ↓
  ├─ can_fee_payer_transfer() [TIP-403 Check]
  ├─ Balance Check
  ├─ Fee Token Validation
  ├─ AMM Liquidity Check
  └─ Keychain Validation
  ↓
Jika valid → Masuk Pool → Eksekusi
```

#### Alur Subblock (Rentan)
```
RPC send_transaction (dengan subblock_proposer)
  ↓
subblock_transactions_tx.send() [BYPASS POOL]
  ↓
subblocks::on_new_subblock_transaction()
  ↓
Hanya disimpan dalam map [TANPA VALIDASI]
  ↓
build_subblock()
  ↓
evm.transact_commit() [LANGSUNG EKSEKUSI]
```

### Kode yang Menunjukkan Celah

#### 1. RPC Handler (Bypass Pool)
```rust
// crates/node/src/rpc/mod.rs:328-340
fn send_transaction(...) -> ... {
    if tx.value().inner().subblock_proposer().is_some() {
        // Send subblock transactions to the subblocks service.
        // ⚠️ BYPASS: Tidak melalui transaction pool validator
        self.subblock_transactions_tx.send(tx.into_value())?;
        Ok(tx_hash)
    } else {
        // Send regular transactions to the transaction pool.
        // ✅ AMAN: Melalui validator
        self.inner.send_transaction(tx).map_err(Into::into)
    }
}
```

#### 2. Subblock Transaction Handler (Tidak Validasi)
```rust
// crates/commonware-node/src/subblocks.rs:227-239
fn on_new_subblock_transaction(&self, transaction: Recovered<TempoTxEnvelope>) {
    // ⚠️ Hanya cek proposer match, tidak validasi compliance
    if !transaction.subblock_proposer()
        .is_some_and(|k| k.matches(self.signer.public_key())) {
        return;
    }
    // ⚠️ Langsung insert tanpa validasi
    txs.insert(*transaction.tx_hash(), Arc::new(transaction));
}
```

#### 3. Build Subblock (Langsung Eksekusi)
```rust
// crates/commonware-node/src/subblocks.rs:703
for (tx_hash, tx) in txs {
    // ⚠️ Langsung eksekusi tanpa validasi
    if let Err(err) = evm.transact_commit(&*tx) {
        warn!("invalid subblock candidate transaction");
        continue;
    }
    // ...
}
```

#### 4. Validasi yang Seharusnya Dipanggil (Tidak Dipanggil)
```rust
// crates/transaction-pool/src/validator.rs:293-310
match state_provider.can_fee_payer_transfer(fee_token, fee_payer, spec) {
    Ok(valid) => {
        if !valid {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(
                    TempoPoolTransactionError::BlackListedFeePayer {
                        fee_token,
                        fee_payer,
                    },
                ),
            );
        }
    }
    // ...
}
```

## Dampak

### Severity: **HIGH**

1. **Compliance Bypass**: Alamat yang masuk blacklist di TIP-403 Policy Registry dapat tetap mengeksekusi transaksi sebagai fee payer
2. **QoS Bypass**: Validasi Payment Lanes (balance, liquidity) dapat dilewati
3. **Integritas Sistem**: Melemahkan mekanisme kontrol akses dan compliance yang telah ditetapkan

### Skenario Serangan

1. Attacker mengetahui public key dari salah satu validator
2. Attacker membuat transaksi dengan:
   - `subblock_proposer` di-set ke validator tersebut
   - `nonce_key` dengan prefix `TEMPO_SUBBLOCK_NONCE_KEY_PREFIX` dan 15 byte pertama dari validator public key
   - Fee payer yang masuk blacklist di TIP-403 Policy Registry
3. Transaksi dikirim melalui RPC `send_raw_transaction`
4. Transaksi diarahkan ke subblocks service, melewati transaction pool validator
5. Transaksi dieksekusi meskipun fee payer masuk blacklist

## Rekomendasi Perbaikan

### 1. Validasi Sebelum Masuk Subblocks Service

Tambahkan validasi di `on_new_subblock_transaction` atau sebelum transaksi masuk ke subblocks service:

```rust
// crates/commonware-node/src/subblocks.rs
fn on_new_subblock_transaction(&self, transaction: Recovered<TempoTxEnvelope>) {
    // Validasi proposer match
    if !transaction.subblock_proposer()
        .is_some_and(|k| k.matches(self.signer.public_key())) {
        return;
    }
    
    // ✅ TAMBAHKAN: Validasi compliance sebelum insert
    let state_provider = match self.node.provider.latest() {
        Ok(provider) => provider,
        Err(_) => return,
    };
    
    // Validasi menggunakan validator yang sama dengan transaction pool
    match self.node.pool.validator().validate_one(
        TransactionOrigin::External,
        TempoPooledTransaction::new(transaction.clone()),
        state_provider,
    ) {
        TransactionValidationOutcome::Valid { .. } => {
            // Valid, boleh insert
        }
        _ => {
            // Invalid, reject
            warn!("Subblock transaction failed validation");
            return;
        }
    }
    
    let mut txs = self.subblock_transactions.lock();
    if txs.len() >= MAX_SUBBLOCK_TXS {
        return;
    }
    txs.insert(*transaction.tx_hash(), Arc::new(transaction));
}
```

### 2. Validasi di build_subblock

Tambahkan validasi sebelum eksekusi di `build_subblock`:

```rust
// crates/commonware-node/src/subblocks.rs:build_subblock
for (tx_hash, tx) in txs {
    if tx.gas_limit() > gas_left {
        continue;
    }
    
    // ✅ TAMBAHKAN: Validasi sebelum eksekusi
    let state_provider = evm.database().state_provider();
    match validator.validate_one(
        TransactionOrigin::External,
        TempoPooledTransaction::new((*tx).clone()),
        state_provider,
    ) {
        TransactionValidationOutcome::Valid { .. } => {
            // Valid, lanjut eksekusi
        }
        _ => {
            warn!(%tx_hash, "subblock transaction failed validation");
            transactions.lock().swap_remove(&tx_hash);
            continue;
        }
    }
    
    if let Err(err) = evm.transact_commit(&*tx) {
        // ...
    }
}
```

### 3. Validasi di validate_subblock

Tambahkan validasi sebelum eksekusi di `validate_subblock`:

```rust
// crates/commonware-node/src/subblocks.rs:validate_subblock
for tx in subblock.transactions_recovered() {
    // ✅ TAMBAHKAN: Validasi sebelum eksekusi
    let state_provider = evm.database().state_provider();
    match validator.validate_one(
        TransactionOrigin::External,
        TempoPooledTransaction::new(tx.clone()),
        state_provider,
    ) {
        TransactionValidationOutcome::Valid { .. } => {
            // Valid, lanjut eksekusi
        }
        _ => {
            return Err(eyre::eyre!("transaction failed validation"));
        }
    }
    
    if let Err(err) = evm.transact_commit(tx) {
        return Err(eyre::eyre!("transaction failed to execute: {err:?}"));
    }
}
```

## Test yang Dibuat

File: `crates/node/tests/it/compliance_bypass_test.rs`

Test ini mencoba:
1. Setup TIP20 token dengan blacklist policy
2. Menambahkan alamat ke blacklist
3. Mengirim transaksi dari alamat yang di-blacklist melalui jalur subblock
4. Memverifikasi bahwa transaksi ditolak (bukan dieksekusi)

## Catatan Tambahan

1. **TIP-403 Checks Selama Eksekusi**: Meskipun TIP-403 checks terjadi selama eksekusi EVM untuk token transfers (di TIP20 precompile), validasi fee payer harus dilakukan SEBELUM eksekusi untuk mencegah gas terbuang dan memastikan compliance.

2. **Validator Key Requirement**: Untuk membuat subblock transaction yang valid, attacker perlu mengetahui validator's public key. Namun, ini bukan hambatan yang signifikan karena:
   - Validator keys dapat diketahui dari on-chain data
   - Attacker dapat menjadi validator sendiri
   - Validator keys dapat diobservasi dari network traffic

3. **Timing**: Validasi harus dilakukan sebelum transaksi masuk ke subblocks service untuk mencegah DoS dan memastikan compliance.

## Status

- ✅ Analisis selesai
- ✅ Test integration dibuat
- ⚠️ Perbaikan belum diimplementasikan
- ⚠️ Review security team diperlukan

## Referensi

- TIP-403 Policy Registry: `docs/pages/protocol/tip403/spec.mdx`
- Transaction Validator: `crates/transaction-pool/src/validator.rs`
- Subblock Implementation: `crates/commonware-node/src/subblocks.rs`
- RPC Handler: `crates/node/src/rpc/mod.rs`

