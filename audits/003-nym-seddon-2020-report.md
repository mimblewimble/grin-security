# Grin 4.0.0-20b45006 Audit

## Summary

There was one in-scope security finding (fixed) during the audit.

Several out-of-scope findings were found, see the [appendix](#appendix) for details.

The overall quality of the Grin codebase is very high, with many descriptive comments, a thorough test suite, and clear coding style.

The Grin security team and developers were very responsive throughout the audit, and reflect a high level of security maturity for the project.

The out-of-scope findings involving memory corruption are related to crates that interface with C libraries, which are notoriously difficult for maintaining Rust's memory-safety guarantees.

Fortunately, there do not appear to be direct remote paths leading to exploitable vulnerabilities. One out-of-band remote vulnerability was found for Slatepack file processing.

Out-of-scope informational findings were found by running `cargo-audit` to discover dependencies with known vulnerabilities. Two of those findings do not appear to affect Grin. It is still recommended to add `cargo-audit` runs to continuous integration tests, even if `cargo-audit` is only run once a week, and/or over commits adding new dependencies.

## Motivation

My name is Nym Seddon, a security researcher with a passion for cryptocurrency and privacy-enhancing technologies.

I took on the Grin audit as a learning experience, and contribution to the cryptocurrency community.

The audit was performed pro-bono, as a practice in [gift economics](https://en.wikipedia.org/wiki/Gift_economy) that makes open-source so great.

## Caveats

- I am **NOT** a Ph.D. researcher
- I am a cryptography practitioner with experience implementing and breaking cryptographic protocols
- I have professional experience auditing software
- I have made a best-effort attempt in the alotted time

All findings and claims should be weighed with the above caveats in mind.

### In-scope findings

- **Critical**: 0
- **High**: 0
- **Medium**: 1
- **Low**: 0
- **Informational**: 0

## Methodology

- **Timespan**: ~14 days
- **Review Commit**:
  - [node - 20b45006](https://github.com/mimblewimble/grin)
  - [wallet - 0fb67706](https://github.com/mimblewimble/grin-wallet)
- **Methods**: manual code + specification review, tool-assisted testing (fuzzing + cargo-audit)

## Audit overview

Started the audit by reading the [Mimblewimble white-paper](https://download.wpsoftware.net/bitcoin/wizardry/mimblewimble.pdf), and checking that the core cryptographic structures match the specification. To the best of my understanding, the Grin implementation accurately follows the Mimblewimble specification, using a modified fork of `libsecp256k1` with additional zero-knowledge proof primitives in a library called [secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp).

While I made an attempt to validate the correctness of implementation, I did not perform a full cryptanalysis of the code nor specification. Additions in `secp256k1-zkp` do not appear to introduce cryptographic errors, but the more cryptanalytic eyes, the better. Future researchers may want to focus efforts on functions dealing with Pedersen commitments and aggregation.

Performed a manual code-review of the diffs since the previous audit performed by [Coinspect](https://github.com/mimblewimble/grin-security/blob/master/audits/002-coinspect-2019-report.pdf), in both the node and wallet repositories.

No effort was made to review [grin-miner](https://github.com/mimblewimble/grin-miner) code, as time ran short. A quick review was made over miner code in the node repository. Plan to further review [Cuckarooz](https://forum.grin.mw/t/introducing-the-final-tweak-cuckarooz/7283) before the `5.0.0` release. 

Along with manual review, performed fuzz-testing, unit-testing for proof-of-concept, and ran cargo-audit (to catch low-hanging fruit).

Special attention was paid to [TransactionPool](https://github.com/mimblewimble/grin/blob/master/pool/src/transaction_pool.rs) code, and a [PR with a fuzz driver](https://github.com/mimblewimble/grin/pull/3396) was opened. Some minor memory leak bugs were found, but nothing security-critical. Further testing is advised, with some added logic for fuzzing multiple transactions of varying kernel features being added to the stem and main transaction pool.

A somewhat light review was made over the No Recent Duplicate kernel feature, and Slatepack transaction workflow specifications. Both specifications/implementations were still under heavy development at the time of review, which made it more sensible to wait for a future code-freeze before conducting a more thorough review.

## No Recent Duplicate (NRD) Kernel Review

NRD kernels are a new kernel feature enabling relative time locks (based on block height) for Grin transactions. At the time of review, NRD kernels were still under heavy development. The base protocol has been specified in Grin [RFC-0013](https://github.com/mimblewimble/grin-rfcs/blob/master/text/0013-nrd-kernels.md), and implemented in the Grin node codebase. The implementation includes adding the NRD kernel feature, logic for handling NRD kernels in the transaction and stem pools, logic for handling NRD kernels in mined blocks, and a thorough test suite. For the parts of the specification that have been coded, the implementation appears to correctly follow the NRD specification.

Payment channel transactions and atomic swaps (two use cases for NRD kernels) were unimplemented at the time of the review.

## Slatepack Review

Slatepack is a new specification for a universal Grin transaction workflow specified in Grin [RFC-0015](https://github.com/mimblewimble/grin-rfcs/blob/master/text/0015-slatepack.md). The implementation is still under heavy development, with slate encryption fully implemented, and enabled by default. Only a limited review of the code was performed, given the development stage.

Brief review was conducted for armor and JSON encoding, encryption, and deserialization. The implementation appears to accurately follow the specification, and only one error was found in the file deserialization code path.

The Slatepack file parsing in `grin-wallet` allows for a potential denial-of-service attack via large Slatepack files. An attacker can thus perform a resource exhaustion attack on Grin wallets by supplying Slatepack files that exceed available memory on the host machine.

While users manually processing Slatepack files are not likely to open hundreds of 100MB files, an exchange will very likely have an automated process for receiving Slatepack files. Exchange implementations may look to `grin-wallet` reference implementation for max file size, find none, and fail to do their own input sanitizing.

## Finding 0: Slatepack file parsing :: Fixed [PR#3407](https://github.com/mimblewimble/grin/pull/3407), [PR#495](https://github.com/mimblewimble/grin-wallet/pull/495)

- **Impact**: Medium
- **Likelihood**: Medium
- **Access**: Out-of-band, remote

There is no code path for reading Slatepack files over the network, so out-of-band transmission of a malicious file is necessary to exploit the vulnerability.

In `grin-wallet`, Slatepack files are parsed and decrypted to further process the inner transaction. There is no check for max file size, which could lead to denial-of-service (DoS).

Slatepack files are opened in `grin-wallet/impls/src/adapters/slatepack.rs:41`:

```
impl<'a> PathToSlatepack<'a> {
...
    pub fn get_slatepack_file_contents(&self) -> Result<Vec<u8>, Error> {
        let mut pub_tx_f = File::open(&self.pathbuf)?;
        let mut data = Vec::new();
        pub_tx_f.read_to_end(&mut data)?;
        Ok(data)
    }
```

File size checks for minimum file size are only implemented after the call to `PathToSlatepack::get_slatepack_file_contents` in `controller/src/command.rs:50`:

```
pub fn unpack<L, C, K>(
    owner_api: &mut Owner<L, C, K>,
    keychain_mask: Option<&SecretKey>,
    args: ReceiveArgs,
) -> Result<(), Error>
...
{
    let mut slatepack = match args.input_file {
        Some(f) => {
            let packer = Slatepacker::new(SlatepackerArgs {
                sender: None,
                recipients: vec![],
                dec_key: None,
            });
            PathToSlatepack::new(f.into(), &packer, true).get_slatepack(false)?
...
```

The check for minimum file size is in `libwallet/src/slatepack/packer.rs:52`:

```
impl<'a> Slatepacker<'a> {
...
    pub fn deser_slatepack(&self, data: Vec<u8>, decrypt: bool) -> Result<Slatepack, Error> {
        // check if data is armored, if so, remove and continue
        if data.len() < super::armor::HEADER.len() {
            let msg = format!("Data too short");
            return Err(ErrorKind::SlatepackDeser(msg).into());
        }
```

The check is too late in the call path, after the file bytes have been read into memory, and no check for maximum size is made.

To exploit the vulnerability:

```
// on a system with less than 20GB of RAM
$ dd if=/dev/zero of=evil.slatepack bs=1M count=20480
$ grin-wallet --input evil.slatepack
```

### Remediations:

Define a maximum size for Slatepack files, possibly max block size as defined in Grin's node repository. Add check for max file size, and move minimum file size check to `PathToSlatepack::get_slatepack_file_contents`.

A fix has been merged with [PR #3407](https://github.com/mimblewimble/grin/pull/3407) in `grin` and [PR #495](https://github.com/mimblewimble/grin-wallet/pull/495) in `grin-wallet`.

## Appendix

### Out-of-scope / Non-security findings

After discussion with the Grin security team, the below findings are considered out-of-scope and/or non-security findings.

Over the course of the audit, there were the following out-of-scope findings (requiring local user access):

- **Critical**:      0
- **High**:          2
- **Medium**:        3
- **Low**:           1
- **Informational**: 3

Grin, as a project, does not consider bugs requiring local user access to be in-scope. This is not an uncommon stance to take, but also not explicitly mentioned anywhere in the Grin security policy or [grin-security](https://github.com/mimblewimble/grin-security) repository. A scoping document (or section in the main security document) would help researchers to not waste Grin security team's or their own time on bugs requiring local access (or are otherwise out-of-scope).

Mistakes were my own, and unfortunately ate up a bit of time on this review. The Grin security team members Daniel Lehnberg and John Woeltz provided helpful, constructive feedback on bug-hunting in the Grin codebase, much appreciation to them both.

#### Finding 0: LMDB database corruption :: Will not fix (out-of-scope)

- **Impact**: High
- **Likelihood**: Low
- **Access**: Local

An attacker with local user access can modify the chain and peer database files (`[lmdb|peer]/data.mdb`, `[lmdb|peer]/lock.mdb`), which can cause
the node to panic, and/or cause a SEGFAULT.

As an example, an attacker can remove the second line from the `lmdb/data.mdb` file:

```
ÞÀï¾ ... (long header, line 1)
ì'y{H  <--- remove this, line 2
```

On the next startup, the grin node will crash with a SEGFAULT:

```
$ cargo run
...
20200629 00:21:42.829 WARN grin::cmd::server - Starting GRIN w/o UI...
Segmentation fault (core dumped)
```

For more information, see the full GDB stack trace in the appendix.

Because the API is exposed as unsafe, and an attacker requires local access to exploit the bug, this is only an out-of-scope, high-impact finding.

Memory corruption can still occur, but further exploits would be needed on the host system to, for example, gain privilege escalation and/or code execution.

If a remote trigger is found for this vulnerabiility, the impact would be critical. However, at the time of writing, no remote trigger has been found.

##### Remediations:

Encrypting the database files at rest at least partially mitigates the risk, especially if an AEAD algorithm is used
(e.g. AES-GCM, ChaCha20-Poly1305, AES-CBC-HMAC, etc.). If any data corruption occurs on the encrypted file, decryption will fail,
and the user can be notified via an error to delete the database. The user can then restart from a fresh sync, or a known-good backup.

Further mitigations would likely involve upstream refactors to `lmdb-zero` and/or `lmdb` to provide fully safe APIs, or switching to a pure-Rust database.

A separate [issue](https://github.com/AltSysrq/lmdb-zero/issues/30) has been opened upstream in `lmdb-zero`.

#### Finding 1: Peers stored plain-text in LMDB :: Will not fix (out-of-scope)

- **Impact**: High
- **Likelihood**: Low
- **Access**: Local

Peer IP data is stored plain-text in the `peer/data.mdb` database. The database has appropriate file permissions (0600),
restricting read-write access to the current user.

However, a local attacker with the same user permissions could also read/write the file.

This is an attack vector on user and peer privacy, though the likelihood is low, and out-of-scope because it requires local access. An attacker could discover all recent/regular peers a user connects to, and even change the IP addresses in the LMDB database to attacker controlled machines.

An attacker with local user permissions could also edit the `grin-server.toml` file to exclusively connect to attacker controlled addresses, but that is a much less covert attack vector. Changing values in the LMDB database is far less likely to be noticed, even by a cautious user.

##### Remediations:

Possible remediations could be to encrypt the entire database at rest (decrypting while the node is running), or to store only the peer entries encrypted. Depending on the expected maximum size of the peer database, peer entries could be kept entirely in memory while the node is running, and only written to disk after encryption.

#### Finding 2: Explicit panic called during SocketAddr deserialization :: Fixed: [PR#3383](https://github.com/mimblewimble/grin/pull/3383)

- **Impact**: Medium
- **Likelihood**: Low
- **Access**: Local

In `p2p/src/types.rs` the `Visitor impl for `PeerAddrs`, a `panic` is explicitly called when converting a `SocketAddr` from string fails:

```
fn visit_seq<M>(self, mut access: M) -> Result<Self::Value, M::Error>
where
        M: SeqAccess<'de>,
{
        let mut peers = Vec::with_capacity(access.size_hint().unwrap_or(0));

        while let Some(entry) = access.next_element::<&str>()? {
                match SocketAddr::from_str(entry) {
                        ...
                        Err(_) => {
                                let socket_addrs = entry
                                        .to_socket_addrs()
                                        .unwrap_or_else(|_| panic!("Unable to resolve DNS: {}", entry));
```

### Remediations:

Since the function already returns a `Result`, the `map_err(|e| ...)?` pattern should be used to bubble up the error instead.

#### Finding 3: Uncontrolled recursion leading to panic in yaml-rust dependency :: Will not fix (out-of-scope)

- **Impact**: Medium
- **Likelihood**: Low
- **Access**: Local

Indefinite recursion in the `yaml-rust` crate could lead to panic when parsing/deserializing YAML configuration files.

A user could provide misconfigured files, or an attacker with local user access could corrupt the configuration to trigger a panic.

##### Remediations:

Upgrade to the latest version of the `yaml-rust` crate.

See the appendix entry for the grin wallet `cargo-audit` report for more information.

#### Finding 4: Panic from file handling error when creating database files :: Fixed: [PR#3364](https://github.com/mimblewimble/grin/pull/3364)

- **Impact**: Low
- **Likelihood**: Low
- **Access**: Local

In `store/src/lmdb.rs:106`, there is the following file creation in the `Store::new()` method:

```
fs::create_dir_all(&full_path)
            .expect("Unable to create directory 'db_root' to store chain_data");
```

Since `Store::new()` already returns a `Result` you can use the `map_err(|e| Error::SomeFileErr("err_msg"))?` to bubble an appropriate message
for callers from other parts of the crate. This would be safer than the current panic.

The impact for this vulnerability is low, because an attacker would need local user privileges to exploit this vulnerability.
Given local user privileges, the attacker has a number of other options to crash the client.

#### Finding 5: Buffer overflow vulnerabilities in ncurses/pancurses TUI dependencies :: Unaffected

- **Impact**: Informational, Grin unaffected
- **Likelihood**: Low
- **Access**: N/A

From a `cargo-audit` run, a buffer overflow vulnerability was found in the `ncurses/pancurses` backends for the `cursive` TUI framework.

No safe upgrade is available at the time of this report.

The Grin node's TUI does not appear to be affected by this vulnerability. User-agent strings are limited by `Hand/Shake` messages,
and even supplying a max-length User-Agent string does not trigger a buffer-overflow.

It is still advisable to move away from an `ncurses`-based TUI.

From the [ncurses-rs README](https://github.com/jeaye/ncurses-rs):

```
The ncurses lib is terribly unsafe and ncurses-rs is only the lightest wrapper it can be.
If you want a safe and idiomatic TUI library for Rust, look elsewhere.
```

##### Remediations:

Change to a different `cursive` backend for \*nix and macOS users, and recommend to Windows users to run the node in no-TUI mode, until
a fix or different backend becomes available for the platform. Potentially default to no-TUI mode on Windows platforms.

See the appendix entry for the grin node `cargo-audit` report for more information.

Original finding by [@thomcc](https://github.com/RustSec/advisory-db/issues/106)

#### Finding 6: Format string vulnerabilities in ncurses/pancurses TUI dependencies :: Unaffected

- **Impact**: Informational, Grin unaffected
- **Likelihood**: Low
- **Access**: N/A

From a `cargo-audit`, a format-string vulnerability was found in the `ncurses/pancurses` backends for the `cursive` TUI framework.

No safe upgrade is available at the time of this report.

Format-string vulnerabilities in C libraries can lead to stack-overflow, reading stack canaries, code execution via return-oriented-programming, etc.

However, it does not appear that the Grin node's TUI is directly affected by the format-string vulnerability. Supplying format sequences, e.g. `%n`,
directly to user-controlled strings like `User Agent` result in the literal characters being displayed, instead of the strings being interpreted as
special format-string characters.

##### Remediations:

Change to a different `cursive` backend for \*nix and macOS users, and recommend to Windows users to run the node in no-TUI mode, until
a fix or different backend becomes available for the platform. Potentially default to no-TUI mode on Windows platforms.

See the appendix entry for the grin node `cargo-audit` report for more information.

Original finding by [@thomcc](https://github.com/RustSec/advisory-db/issues/106)

#### Finding 8: Unchecked unwraps in secp256k1-zkp :: Will not fix (out-of-scope)

- **Impact**: Informational, non-security issue
- **Likelihood**: Very low
- **Access**: Remote

In `grin_secp256k1zkp/src/pedersen.rs:496-497`, there are unchecked unwraps on `commit_parse` calls:

```
pub fn commit_sum(
...
    let pos = map_vec!(positive, |p| self.commit_parse(p.0).unwrap());
    let neg = map_vec!(negative, |n| self.commit_parse(n.0).unwrap());
```

`commit_parse` doesn't appear to be able to return an `Error`, at the moment, so these unwraps are likely safe.

However, for a bit of defensive programming, would recommend using the `?` operator to bubble up errors (especially since the plumbing is already in place).

A few lines above, in `verify_commit_sum`, you may need to change the return to `Result<bool, Error>`, and use the `?` operator in lines 475-476:

```
pub fn verify_commit_sum(&self, positive: Vec<Commitment>, negative: Vec<Commitment>) -> bool {
    let pos = map_vec!(positive, |p| { self.commit_parse(p.0).unwrap() });
    let neg = map_vec!(negative, |n| self.commit_parse(n.0).unwrap());
```

These are informational findings, since the unwraps appear safe, and recommendations are for future-proofing / defensive programming.

#### Grin node cargo-audit report

```
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 87 security advisories (from .cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (318 crate dependencies)

ID:       RUSTSEC-2019-0006
Crate:    ncurses
Version:  5.99.0
Date:     2019-06-15
URL:      https://rustsec.org/advisories/RUSTSEC-2019-0006
Title:    Buffer overflow and format vulnerabilities in functions exposed without unsafe
Solution:  No safe upgrade is available!
Dependency tree:
ncurses 5.99.0
└── pancurses 0.16.1
    └── cursive 0.15.0
        └── grin 4.0.0-beta.2

ID:       RUSTSEC-2019-0005
Crate:    pancurses
Version:  0.16.1
Date:     2019-06-15
URL:      https://rustsec.org/advisories/RUSTSEC-2019-0005
Title:    Format string vulnerabilities in `pancurses`
Solution:  No safe upgrade is available!
Dependency tree:
pancurses 0.16.1
└── cursive 0.15.0
    └── grin 4.0.0-beta.2

ID:       RUSTSEC-2018-0006
Crate:    yaml-rust
Version:  0.3.5
Date:     2018-09-17
URL:      https://rustsec.org/advisories/RUSTSEC-2018-0006
Title:    Uncontrolled recursion leads to abort in deserialization
Solution:  upgrade to >= 0.4.1
Dependency tree:
yaml-rust 0.3.5

warning: 1 warning found

Crate:  net2
Title:  `net2` crate has been deprecated; use `socket2` instead
Date:   2020-05-01
URL:    https://rustsec.org/advisories/RUSTSEC-2020-0016
Dependency tree:
net2 0.2.34
├── miow 0.2.1
└── mio 0.6.22
    ├── tokio 0.2.21
    │   ├── tokio-util 0.3.1
    │   ├── tokio-util 0.2.0
    │   ├── tokio-rustls 0.13.1
    │   │   ├── hyper-rustls 0.20.0
    │   │   │   ├── grin_servers 4.0.0-beta.2
    │   │   │   │   ├── grin_config 4.0.0-beta.2
    │   │   │   │   │   └── grin 4.0.0-beta.2
    │   │   │   │   └── grin 4.0.0-beta.2
    │   │   │   └── grin_api 4.0.0-beta.2
    │   │   │       ├── grin_servers 4.0.0-beta.2
    │   │   │       └── grin 4.0.0-beta.2
    │   │   └── grin_api 4.0.0-beta.2
    │   ├── tokio-io-timeout 0.4.0
    │   │   └── hyper-timeout 0.3.1
    │   │       └── grin_api 4.0.0-beta.2
    │   ├── hyper-timeout 0.3.1
    │   ├── hyper-rustls 0.20.0
    │   ├── hyper 0.13.6
    │   │   ├── hyper-timeout 0.3.1
    │   │   ├── hyper-rustls 0.20.0
    │   │   ├── grin_servers 4.0.0-beta.2
    │   │   └── grin_api 4.0.0-beta.2
    │   ├── h2 0.2.5
    │   │   └── hyper 0.13.6
    │   ├── grin_servers 4.0.0-beta.2
    │   └── grin_api 4.0.0-beta.2
    ├── mio-uds 0.6.8
    │   └── tokio 0.2.21
    └── mio-named-pipes 0.1.6
        └── tokio 0.2.21

Crate:  spin
Title:  spin is no longer actively maintained
Date:   2019-11-21
URL:    https://rustsec.org/advisories/RUSTSEC-2019-0031
Dependency tree:
spin 0.5.2
└── ring 0.16.14
    ├── webpki 0.21.3
    │   ├── tokio-rustls 0.13.1
    │   │   ├── hyper-rustls 0.20.0
    │   │   │   ├── grin_servers 4.0.0-beta.2
    │   │   │   │   ├── grin_config 4.0.0-beta.2
    │   │   │   │   │   └── grin 4.0.0-beta.2
    │   │   │   │   └── grin 4.0.0-beta.2
    │   │   │   └── grin_api 4.0.0-beta.2
    │   │   │       ├── grin_servers 4.0.0-beta.2
    │   │   │       └── grin 4.0.0-beta.2
    │   │   └── grin_api 4.0.0-beta.2
    │   ├── rustls 0.17.0
    │   │   ├── tokio-rustls 0.13.1
    │   │   ├── rustls-native-certs 0.3.0
    │   │   │   └── hyper-rustls 0.20.0
    │   │   ├── hyper-rustls 0.20.0
    │   │   └── grin_api 4.0.0-beta.2
    │   └── hyper-rustls 0.20.0
    ├── sct 0.6.0
    │   ├── rustls 0.17.0
    │   └── ct-logs 0.6.0
    │       └── hyper-rustls 0.20.0
    ├── rustls 0.17.0
    └── grin_api 4.0.0-beta.2

Crate:  term
Title:  term is looking for a new maintainer
Date:   2018-11-19
URL:    https://rustsec.org/advisories/RUSTSEC-2018-0015
Dependency tree:
term 0.6.1
└── grin 4.0.0-beta.2

error: Vulnerable crates found!
error: 3 vulnerabilities found!
warning: 1 warning found!
```

#### Grin wallet cargo-audit report

```
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 87 security advisories (from .cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (388 crate dependencies)

ID:       RUSTSEC-2018-0006
Crate:    yaml-rust
Version:  0.3.5
Date:     2018-09-17
URL:      https://rustsec.org/advisories/RUSTSEC-2018-0006
Title:    Uncontrolled recursion leads to abort in deserialization
Solution:  upgrade to >= 0.4.1
Dependency tree:
yaml-rust 0.3.5

warning: 2 warnings found

Crate:  block-cipher-trait
Title:  crate has been renamed to `block-cipher`
Date:   2020-05-26
URL:    https://rustsec.org/advisories/RUSTSEC-2020-0018
Dependency tree:
block-cipher-trait 0.6.2
├── ctr 0.3.2
│   └── aes-ctr 0.3.0
│       └── age 0.4.0
│           └── grin_wallet_libwallet 4.0.0-rc.1
│               ├── grin_wallet_impls 4.0.0-rc.1
│               │   ├── grin_wallet_controller 4.0.0-rc.1
│               │   │   └── grin_wallet 4.0.0-rc.1
│               │   ├── grin_wallet_api 4.0.0-rc.1
│               │   │   ├── grin_wallet_controller 4.0.0-rc.1
│               │   │   └── grin_wallet 4.0.0-rc.1
│               │   └── grin_wallet 4.0.0-rc.1
│               ├── grin_wallet_controller 4.0.0-rc.1
│               ├── grin_wallet_api 4.0.0-rc.1
│               └── grin_wallet 4.0.0-rc.1
├── blowfish 0.4.0
│   └── bcrypt-pbkdf 0.1.0
│       └── age 0.4.0
├── block-modes 0.3.3
│   └── age 0.4.0
├── age 0.4.0
├── aesni 0.6.0
│   ├── aes-ctr 0.3.0
│   └── aes 0.3.2
│       └── age 0.4.0
├── aes-soft 0.3.3
│   ├── aes-ctr 0.3.0
│   └── aes 0.3.2
└── aes 0.3.2

Crate:  net2
Title:  `net2` crate has been deprecated; use `socket2` instead
Date:   2020-05-01
URL:    https://rustsec.org/advisories/RUSTSEC-2020-0016
Dependency tree:
net2 0.2.34
├── miow 0.2.1
└── mio 0.6.22
    ├── tokio 0.2.21
    │   ├── tokio-util 0.3.1
    │   │   └── h2 0.2.5
    │   │       └── hyper 0.13.6
    │   │           ├── hyper-tls 0.4.1
    │   │           │   └── hyper-socks2-mw 0.4.4
    │   │           │       └── grin_wallet_impls 4.0.0-rc.1
    │   │           │           ├── grin_wallet_controller 4.0.0-rc.1
    │   │           │           │   └── grin_wallet 4.0.0-rc.1
    │   │           │           ├── grin_wallet_api 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │           │           │   └── grin_wallet 4.0.0-rc.1
    │   │           │           └── grin_wallet 4.0.0-rc.1
    │   │           ├── hyper-timeout 0.3.1
    │   │           │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │           │   └── grin_api 4.0.0-rc.1
    │   │           │       └── grin_wallet_util 4.0.0-rc.1
    │   │           │           ├── grin_wallet_libwallet 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_api 4.0.0-rc.1
    │   │           │           │   └── grin_wallet 4.0.0-rc.1
    │   │           │           ├── grin_wallet_impls 4.0.0-rc.1
    │   │           │           ├── grin_wallet_controller 4.0.0-rc.1
    │   │           │           ├── grin_wallet_config 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_libwallet 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │           │           │   ├── grin_wallet_api 4.0.0-rc.1
    │   │           │           │   └── grin_wallet 4.0.0-rc.1
    │   │           │           ├── grin_wallet_api 4.0.0-rc.1
    │   │           │           └── grin_wallet 4.0.0-rc.1
    │   │           ├── hyper-socks2-mw 0.4.4
    │   │           ├── hyper-rustls 0.20.0
    │   │           │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │           │   └── grin_api 4.0.0-rc.1
    │   │           ├── grin_wallet_impls 4.0.0-rc.1
    │   │           ├── grin_wallet_controller 4.0.0-rc.1
    │   │           └── grin_api 4.0.0-rc.1
    │   ├── tokio-tls 0.3.1
    │   │   └── hyper-tls 0.4.1
    │   ├── tokio-rustls 0.13.1
    │   │   ├── hyper-rustls 0.20.0
    │   │   └── grin_api 4.0.0-rc.1
    │   ├── tokio-io-timeout 0.4.0
    │   │   └── hyper-timeout 0.3.1
    │   ├── hyper-tls 0.4.1
    │   ├── hyper-timeout 0.3.1
    │   ├── hyper-socks2-mw 0.4.4
    │   ├── hyper-rustls 0.20.0
    │   ├── hyper 0.13.6
    │   ├── h2 0.2.5
    │   ├── grin_wallet_impls 4.0.0-rc.1
    │   ├── grin_wallet_controller 4.0.0-rc.1
    │   ├── grin_api 4.0.0-rc.1
    │   └── async-socks5 0.3.1
    │       └── hyper-socks2-mw 0.4.4
    ├── mio-uds 0.6.8
    │   └── tokio 0.2.21
    └── mio-named-pipes 0.1.6
        └── tokio 0.2.21

Crate:  spin
Title:  spin is no longer actively maintained
Date:   2019-11-21
URL:    https://rustsec.org/advisories/RUSTSEC-2019-0031
Dependency tree:
spin 0.5.2
└── ring 0.16.14
    ├── webpki 0.21.3
    │   ├── tokio-rustls 0.13.1
    │   │   ├── hyper-rustls 0.20.0
    │   │   │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │   │   │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │   │   │   │   └── grin_wallet 4.0.0-rc.1
    │   │   │   │   ├── grin_wallet_api 4.0.0-rc.1
    │   │   │   │   │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │   │   │   │   └── grin_wallet 4.0.0-rc.1
    │   │   │   │   └── grin_wallet 4.0.0-rc.1
    │   │   │   └── grin_api 4.0.0-rc.1
    │   │   │       └── grin_wallet_util 4.0.0-rc.1
    │   │   │           ├── grin_wallet_libwallet 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_api 4.0.0-rc.1
    │   │   │           │   └── grin_wallet 4.0.0-rc.1
    │   │   │           ├── grin_wallet_impls 4.0.0-rc.1
    │   │   │           ├── grin_wallet_controller 4.0.0-rc.1
    │   │   │           ├── grin_wallet_config 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_libwallet 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_impls 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_controller 4.0.0-rc.1
    │   │   │           │   ├── grin_wallet_api 4.0.0-rc.1
    │   │   │           │   └── grin_wallet 4.0.0-rc.1
    │   │   │           ├── grin_wallet_api 4.0.0-rc.1
    │   │   │           └── grin_wallet 4.0.0-rc.1
    │   │   └── grin_api 4.0.0-rc.1
    │   ├── rustls 0.17.0
    │   │   ├── tokio-rustls 0.13.1
    │   │   ├── rustls-native-certs 0.3.0
    │   │   │   └── hyper-rustls 0.20.0
    │   │   ├── hyper-rustls 0.20.0
    │   │   └── grin_api 4.0.0-rc.1
    │   └── hyper-rustls 0.20.0
    ├── sct 0.6.0
    │   ├── rustls 0.17.0
    │   └── ct-logs 0.6.0
    │       └── hyper-rustls 0.20.0
    ├── rustls 0.17.0
    ├── grin_wallet_impls 4.0.0-rc.1
    ├── grin_wallet_controller 4.0.0-rc.1
    ├── grin_wallet_api 4.0.0-rc.1
    └── grin_api 4.0.0-rc.1

Crate:  term
Title:  term is looking for a new maintainer
Date:   2018-11-19
URL:    https://rustsec.org/advisories/RUSTSEC-2018-0015
Dependency tree:
term 0.5.2

Crate:  term
Title:  term is looking for a new maintainer
Date:   2018-11-19
URL:    https://rustsec.org/advisories/RUSTSEC-2018-0015
Dependency tree:
term 0.6.1

Crate:    crossbeam-queue
Version:  0.2.2
Warning:  package has been yanked!
Dependency tree:
crossbeam-queue 0.2.2
└── rayon-core 1.7.0
    └── rayon 1.3.0
        └── sysinfo 0.14.5
            └── grin_wallet_impls 4.0.0-rc.1
                ├── grin_wallet_controller 4.0.0-rc.1
                │   └── grin_wallet 4.0.0-rc.1
                ├── grin_wallet_api 4.0.0-rc.1
                │   ├── grin_wallet_controller 4.0.0-rc.1
                │   └── grin_wallet 4.0.0-rc.1
                └── grin_wallet 4.0.0-rc.1

error: Vulnerable crates found!
error: 1 vulnerability found!
warning: 2 warnings found!
```

#### GDB stack trace of LMDB SEGFAULT

```
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x0000559bc422df9a in mdb_node_search (mc=mc@entry=0x7ffc6d47aff0, key=key@entry=0x7ffc6d47afa0,
    exactp=exactp@entry=0x7ffc6d47aeac) at mdb/libraries/liblmdb/mdb.c:5116
5116                            i = (low + high) >> 1;
warning: Missing auto-load script at offset 0 in section .debug_gdb_scripts
of file grin/target/debug/grin.
Use `info auto-load python-scripts [REGEXP]' to list them.
(gdb) bt full
#0  0x0000559bc422df9a in mdb_node_search (mc=mc@entry=0x7ffc6d47aff0, key=key@entry=0x7ffc6d47afa0,
    exactp=exactp@entry=0x7ffc6d47aeac) at mdb/libraries/liblmdb/mdb.c:5116
        i = 0
        nkeys = 2147483640
        low = 0
        high = 2147483639
        rc = 0
        mp = 0x7ff24f53f000
        node = 0x0
        nodekey = {mv_size = 140722141973672, mv_data = 0x7ff257a11474 <malloc+116>}
        cmp = 0x559bc422e690 <mdb_cmp_memn>
#1  0x0000559bc42311d0 in mdb_page_search_root (mc=mc@entry=0x7ffc6d47aff0, key=key@entry=0x7ffc6d47afa0, flags=flags@entry=0)
    at mdb/libraries/liblmdb/mdb.c:5295
        exact = 21915
        node = <optimized out>
        i = <optimized out>
        mp = 0x7ff24f53f000
        rc = <optimized out>
        __func__ = "mdb_page_search_root"
#2  0x0000559bc42314ae in mdb_page_search (mc=mc@entry=0x7ffc6d47aff0, key=key@entry=0x7ffc6d47afa0, flags=flags@entry=0)
    at mdb/libraries/liblmdb/mdb.c:5446
        rc = <optimized out>
        root = <optimized out>
        __func__ = "mdb_page_search"
#3  0x0000559bc4231b94 in mdb_cursor_set (mc=mc@entry=0x7ffc6d47aff0, key=key@entry=0x7ffc6d47afa0,
    data=data@entry=0x7ffc6d47afb0, op=op@entry=MDB_SET, exactp=exactp@entry=0x7ffc6d47af9c)
    at mdb/libraries/liblmdb/mdb.c:5905
        rc = <optimized out>
        mp = <optimized out>
        leaf = <optimized out>
        __func__ = "mdb_cursor_set"
#4  0x0000559bc423889d in mdb_dbi_open (txn=0x559bc56e35a0, name=0x559bc56e1360 "chain", flags=262144, dbi=0x7ffc6d47b284)
    at mdb/libraries/liblmdb/mdb.c:9549
        key = {mv_size = 5, mv_data = 0x559bc56e1360}
        data = {mv_size = 94127520619424,
          mv_data = 0x559bc420f96d <<supercow::ext::BoxedStorage as supercow::ext::OwnedStorage<A,B>>::allocate_b+237>}
        i = <optimized out>
        mc = {mc_next = 0x0, mc_backup = 0x0, mc_xcursor = 0x0, mc_txn = 0x559bc56e35a0, mc_dbi = 1, mc_db = 0x559bc56e3658,
          mc_dbx = 0x559bc56e23d0, mc_dbflag = 0x559bc56e3881 "\030", mc_snum = 1, mc_top = 0, mc_flags = 0, mc_pg = {
            0x7ff24f53f000, 0x559bc56e1ba0, 0x7ff257a1035a <_int_malloc+2858>, 0x559bc56e1ba0, 0x7ff257b46a40 <main_arena+96>,
            0x0, 0x559bc4207691 <supercow::Supercow<OWNED,BORROWED,SHARED,STORAGE,PTR>::shared_nocvt+161>, 0x20, 0x6,
            0x559b00000002, 0x559bc420f880 <<supercow::ext::BoxedStorage as supercow::ext::OwnedStorage<A,B>>::allocate_b>,
            0x8a8d0514e9fda23d, 0x0, 0x3000000002, 0x3fb80000006e, 0x0, 0x89bd8be9b4ae300, 0x559bc56dff00, 0x559bc56e22a0,
            0x559bc56e35a0, 0x0, 0x0, 0x559bc56e1360, 0x6, 0x559bc56e1360, 0x6,
            0x559bc4209fc4 <std::ffi::c_str::CStr::as_ptr+20>, 0x559bc56e1360, 0x559bc56e1360, 0x6,
            0x559bc42090f7 <lmdb_zero::dbi::Database::open::{{closure}}+39>, 0x559bc56e1360}, mc_ki = {0, 0, 0, 0, 4960,
            50542, 21915, 0, 600, 50211, 21915, 0, 45704, 27975, 32764, 0, 8306, 50208, 21915, 0, 4960, 50542, 21915, 0, 0, 0,
            0, 0, 45704, 27975, 32764, 0}}
        dummy = {md_pad = 8, md_flags = 0, md_depth = 0, md_branch_pages = 94127520619424, md_leaf_pages = 94127520619424,
          md_overflow_pages = 94127520619424, md_entries = 94127513160416, md_root = 94127520620368}
        rc = <optimized out>
        dbflag = 28
        exact = 0
        unused = <optimized out>
        seq = <optimized out>
        namedup = <optimized out>
        len = 5
#5  0x0000559bc4208bdc in lmdb_zero::dbi::Database::open (env=..., name=..., options=0x7ffc6d47be88)
    at .cargo/registry/src/github.com-1ecc6299db9ec823/lmdb-zero-0.4.4/src/dbi.rs:720
        wrapped_tx = lmdb_zero::tx::TxHandle (0x559bc56e35a0)
        txn_flags = 0
        raw_tx = 0x559bc56e35a0
        locked_dbis = std::sync::mutex::MutexGuard<std::collections::hash::set::HashSet<u32, std::collections::hash::map::RandomState>> {lock: 0x559bc56dff80, poison: std::sys_common::poison::Guard {panicking: false}}
        name_cstr = core::option::Option<std::ffi::c_str::CString>::Some(std::ffi::c_str::CString {inner: alloc::boxed::Box<[u8]> {data_ptr: 0x559bc56e1360 "chain\000", length: 6}})
        raw = 0
        env = supercow::Supercow<lmdb_zero::env::Environment, lmdb_zero::env::Environment, alloc::boxed::Box<DefaultFeatures>, supercow::ext::BoxedStorage, *const lmdb_zero::env::Environment> {ptr: 0x559bc56dff70, mode: 0x559bc56e1ba1, storage: supercow::ext::BoxedStorage, _owned: core::marker::PhantomData<lmdb_zero::env::Environment>, _borrowed: core::marker::PhantomData<&lmdb_zero::env::Environment>, _shared: core::marker::PhantomData<alloc::boxed::Box<DefaultFeatures>>}
#6  0x0000559bc41fdb82 in grin_store::lmdb::Store::new (root_path=..., env_name=..., db_name=..., max_readers=...)
    at store/src/lmdb.rs:133
        w = lock_api::rwlock::RwLockWriteGuard<parking_lot::raw_rwlock::RawRwLock, core::option::Option<alloc::sync::Arc<lmdb_zero::dbi::Database>>> {rwlock: 0x559bc56e16b0, marker: core::marker::PhantomData<(&mut core::option::Option<alloc::sync::Arc<lmdb_zero::dbi::Database>>, lock_api::GuardNoSend)>}
        res = grin_store::lmdb::Store {env: alloc::sync::Arc<lmdb_zero::env::Environment> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<lmdb_zero::env::Environment>> {pointer: 0x559bc56dff60}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<lmdb_zero::env::Environment>>}, db: alloc::sync::Arc<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, core::option::Option<alloc::sync::Arc<lmdb_zero::dbi::Database>>>> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, core::option::Option<alloc::sync::Arc<lmdb_zero::dbi::Database>>>>> {pointer: 0x559bc56e16a0}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, core::option::Option<alloc::sync::Arc<lmdb_zero::dbi::Database>>>>>}, name: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e2280 "chain", '#' <repeats 16 times>, "\n[s\001\001\000", _marker: core::marker::PhantomData<u8>}, cap: 5, alloc: alloc::alloc::Global}, len: 5}}, version: grin_core::ser::ProtocolVersion (2), alloc_chunk_size: 134217728}
        env = lmdb_zero::env::Environment {env: lmdb_zero::env::EnvHandle (0x559bc56e22a0, true), open_dbis: std::sync::mutex::Mutex<std::collections::hash::set::HashSet<u32, std::collections::hash::map::RandomState>> {inner: 0x559bc56e1610, poison: std::sys_common::poison::Flag {failed: core::sync::atomic::AtomicBool {v: core::cell::UnsafeCell<u8> {value: 0}}}, data: core::cell::UnsafeCell<std::collections::hash::set::HashSet<u32, std::collections::hash::map::RandomState>> {value: std::collections::hash::set::HashSet<u32, std::collections::hash::map::RandomState> {map: std::collections::hash::map::HashMap<u32, (), std::collections::hash::map::RandomState> {base: hashbrown::map::HashMap<u32, (), std::collections::hash::map::RandomState> {hash_builder: std::c
ollections::hash::map::RandomState {k0: 9983641536333455933, k1: 6925433874672789264}, table: hashbrown::raw::RawTable<(u32, ())> {bucket_mask: 0, ctrl: core::ptr::non_null::NonNull<u8> {pointer: 0x559bc49f6480 <hashbrown::raw::sse2::Group::static_empty::ALIGNED_BYTES> '\377' <repeats 16 times>, "\001\000"}, data: core::ptr::non_null::NonNull<(u32, ())> {pointer: 0x4}, growth_left: 0, items: 0, marker: core::marker::PhantomData<(u32, ())>}}}}}}}
        alloc_chunk_size = 134217728
        env_builder = lmdb_zero::env::EnvBuilder {env: lmdb_zero::env::EnvHandle (0x559bc56e22a0, true)}
        full_path = alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e1670 ".grin/main/chain_data/lmdbai1\000", _marker: core::marker::PhantomData<u8>}, cap: 38, alloc: alloc::alloc::Global}, len: 38}}
        db_name = alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e2280 "chain", '#' <repeats 16 times>, "\n[s\001\001\000", _marker: core::marker::PhantomData<u8>}, cap: 5, alloc: alloc::alloc::Global}, len: 5}}
        name = alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e1f50 "`\377mśU\000", _marker: core::marker::PhantomData<u8>}, cap: 4, alloc: alloc::alloc::Global}, len: 4}}
#7  0x0000559bc411aa46 in grin_chain::store::ChainStore::new (db_root=...) at chain/src/store.rs:57
No locals.
#8  0x0000559bc417091b in grin_chain::chain::Chain::init (db_root=..., adapter=..., genesis=...,
    pow_verifier=0x559bc42909a0 <grin_core::pow::verify_size>, verifier_cache=..., archive_mode=false)
    at chain/src/chain.rs:172
No locals.
#9  0x0000559bc3661056 in grin_servers::grin::server::Server::new (config=...) at servers/src/grin/server.rs:197
        genesis = grin_core::core::block::Block {header: grin_core::core::block::BlockHeader {version: grin_core::core::block::HeaderVersion (1), height: 0, prev_hash: grin_core::core::hash::Hash ([
                0 <repeats 32 times>]), prev_root: grin_core::core::hash::Hash ([0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 139, 195, 47,
                67, 39, 127, 233, 192, 99, 185, 201, 158, 162, 82, 180, 131, 148, 29, 205, 6, 226,
                23]), timestamp: chrono::datetime::DateTime<chrono::offset::utc::Utc> {datetime: chrono::naive::datetime::NaiveDateTime {date: chrono::naive::date::NaiveDate {ymdf: 16539903}, time: chrono::naive::time::NaiveTime {secs: 57686, frac: 0}}, offset: chrono::offset::utc::Utc}, output_root: grin_core::core::hash::Hash ([250, 117, 102, 210, 117, 0, 108, 108, 70, 120,
                118, 117, 143, 43, 200, 126, 76, 235, 210, 2, 10, 233, 207, 159, 41, 76, 98, 23, 130, 141, 104,
                114]), range_proof_root: grin_core::core::hash::Hash ([27, 127, 255, 37, 154, 238, 62, 223, 181, 134, 124, 71,
                117, 228, 225, 113, 120, 38, 184, 67, 205, 166, 104, 94, 81, 64, 68, 46, 206, 123, 252,
                46]), kernel_root: grin_core::core::hash::Hash ([232, 187, 9, 106, 115, 203, 230, 224, 153, 150, 137, 101,
                245, 52, 47, 193, 112, 46, 226, 128, 40, 2, 144, 34, 134, 220, 240, 242, 121, 227, 38,
                191]), total_kernel_offset: grin_keychain::types::BlindingFactor ([
                0 <repeats 32 times>]), output_mmr_size: 1, kernel_mmr_size: 1, pow: grin_core::pow::types::ProofOfWork {total_difficulty: grin_core::pow::types::Difficulty {num: 17179869184}, secondary_scaling: 1856, nonce: 41, proof: grin_core::pow::types::Proof {edge_bits: 29, nonces: alloc::vec::Vec<u64> {buf: alloc::raw_vec::RawVec<u64, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u64> {pointer: 0x559bc56e1700, _marker: core::marker::PhantomData<u64>}, cap: 42, alloc: alloc::alloc::Global}, len: 42}}}}, body: grin_core::core::transaction::TransactionBody {inputs: alloc::vec::Vec<grin_core::core::transaction::Input> {buf: alloc::raw_vec::RawVec<grin_core::core::transaction::Input, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_core::core::transaction::Input> {pointer: 0x1, _marker: core::marker::PhantomData<grin_core::core::transaction::Input>}, cap: 0, alloc: alloc::alloc::Global}, len: 0}, outputs: alloc::vec::Vec<grin_core::core::transaction::Output> {buf: alloc::raw_vec::RawVec<grin_core::core::transaction::Output, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_core::core::transaction::Output> {pointer: 0x559bc56e1bc0, _marker: core::marker::PhantomData<grin_core::core::transaction::Output>}, cap: 1, alloc: alloc::alloc::Global}, len: 1}, kernels: alloc::vec::Vec<grin_core::core::transaction::TxKernel> {buf: alloc::raw_vec::RawVec<grin_core::cor--Type <RET> for more, q to quit, c to continue without paging--
e::transaction::TxKernel, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_core::core::transaction::TxKernel> {pointer: 0x559bc56e1060, _marker: core::marker::PhantomData<grin_core::core::transaction::TxKernel>}, cap: 1, alloc: alloc::alloc::Global}, len: 1}}}
        chain_adapter = alloc::sync::Arc<grin_servers::common::adapters::ChainToPoolAndNetAdapter<grin_servers::common::adapters::PoolToChainAdapter, grin_servers::common::adapters::PoolToNetAdapter, grin_core::core::verifier_cache::LruVerifierCache>> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<grin_servers::common::adapters::ChainToPoolAndNetAdapter<grin_servers::common::adapters::PoolToChainAdapter, grin_servers::common::adapters::PoolToNetAdapter, grin_core::core::verifier_cache::LruVerifierCache>>> {pointer: 0x559bc56ddad0}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<grin_servers::common::adapters::ChainToPoolAndNetAdapter<grin_servers::common::adapters::PoolToChainAdapter, grin_servers::common::adapters::PoolToNetAdapter, grin_core::core::verifier_cache::LruVerifierCache>>>}
        sync_state = alloc::sync::Arc<grin_chain::types::SyncState> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<grin_chain::types::SyncState>> {pointer: 0x559bc56e14f0}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<grin_chain::types::SyncState>>}
        tx_pool = alloc::sync::Arc<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, grin_pool::transaction_pool::TransactionPool<grin_servers::common::adapters::PoolToChainAdapter, grin_servers::common::adapters::PoolToNetAdapter, grin_core::core::verifier_cache::LruVerifierCache>>> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, grin_pool::transaction_pool::TransactionPool<grin_servers::common::adapters::PoolToChainAdapter, grin_servers::common::adapters::PoolToNetAdapter, grin_core::core::verifier_cache::LruVerifierCache>>>> {pointer: 0x559bc56dd290}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, grin_pool::transaction_pool::TransactionPool<grin_servers::common::adapters::PoolToChainAdapter, grin_servers::common::adapters::PoolToNetAdapter, grin_core::core::verifier_cache::LruVerifierCache>>>>}
        pool_net_adapter = alloc::sync::Arc<grin_servers::common::adapters::PoolToNetAdapter> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<grin_servers::common::adapters::PoolToNetAdapter>> {pointer: 0x559bc56dfac0}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<grin_servers::common::adapters::PoolToNetAdapter>>}
        pool_adapter = alloc::sync::Arc<grin_servers::common::adapters::PoolToChainAdapter> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<grin_servers::common::adapters::PoolToChainAdapter>> {pointer: 0x559bc56e1490}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<grin_servers::common::adapters::PoolToChainAdapter>>}
        verifier_cache = alloc::sync::Arc<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, grin_core::core::verifier_cache::LruVerifierCache>> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, grin_core::core::verifier_cache::LruVerifierCache>>> {pointer: 0x559bc56e13d0}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<lock_api::rwlock::RwLock<parking_lot::raw_rwlock::RawRwLock, grin_core::core::verifier_cache::LruVerifierCache>>>}
        stop_state = alloc::sync::Arc<grin_util::StopState> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<grin_util::StopState>> {pointer: 0x559bc56e13b0}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<grin_util::StopState>>}
        archive_mode = false
        lock_file = alloc::sync::Arc<std::fs::File> {ptr: core::ptr::non_null::NonNull<alloc::sync::ArcInner<std::fs::File>> {pointer: 0x559bc56e1160}, phantom: core::marker::PhantomData<alloc::sync::ArcInner<std::fs::File>>}
#10 0x0000559bc3128567 in grin_servers::grin::server::Server::start (config=..., logs_rx=..., info_callback=...)
    at grin/servers/src/grin/server.rs:104
        test_miner_wallet_url = core::option::Option<alloc::string::String>::None
        enable_test_miner = core::option::Option<bool>::Some(false)
        mining_config = core::option::Option<grin_servers::common::types::StratumServerConfig>::Some(grin_servers::common::types::StratumServerConfig {enable_stratum_server: core::option::Option<bool>::Some(false), stratum_server_addr: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56d9fc0 "127.0.0.1:3416\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}), attempt_time_per_block: 15, minimum_share_difficulty: 1, wallet_listener_url
: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56ddb40 "http://127.0.0.1:3415\000", _marker: core::marker::PhantomData<u8>}, cap: 21, alloc: alloc::alloc::Global}, len: 21}}, burn_reward: false})
#11 0x0000559bc319a89a in grin::cmd::server::start_server_tui (config=..., logs_rx=...) at src/bin/cmd/server.rs:61
No locals.
#12 0x0000559bc319a520 in grin::cmd::server::start_server (config=..., logs_rx=...) at src/bin/cmd/server.rs:36
No locals.
#13 0x0000559bc319b039 in grin::cmd::server::server_command (server_args=..., global_config=..., logs_rx=...)
    at src/bin/cmd/server.rs:136
        server_config = grin_servers::common::types::ServerConfig {db_root: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e1300 ".grin/main/chain_datao disab1\000", _marker: core::marker::PhantomData<u8>}, cap: 33, alloc: alloc::alloc::Global}, len: 33}}, api_http_addr: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0bf0 "127.0.0.1:3413\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}, api_secret_path: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56da600 ".grin/main/.api_secret\000", _marker: core::marker::PhantomData<u8>}, cap: 34, alloc: alloc::alloc::Global}, len: 34}}), foreign_api_secret_path: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0c10 ".foreign_api_secretace\nf!\000", _marker: core::marker::PhantomData<u8>}, cap: 19, alloc: alloc::alloc::Global}, len: 19}}), tls_certificate_file: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 72151721558543648, alloc: alloc::alloc::Global}, len: 140722141951728}}), tls_certificate_key: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 94127520607512, alloc: alloc::alloc::Global}, len: 94127520585155}}), chain_type: grin_core::global::ChainTypes::Mainnet, chain_validation_mode: grin_servers::common::types::ChainValidationMode::Disabled, archive_mode: core::option::Option<bool>::Some(false), skip_sync_wait: core::option::Option<bool>::Some(false), run_tui: core::option::Option<bool>::Some(false), run_test_miner: core::option::Option<bool>::Some(false), test_miner_wallet_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 0, alloc: alloc::alloc::Global}, len: 3}}), p2p_config: grin_p2p::types::P2PConfig {host: <error reading variable>, port: 3414, seeding_type: grin_p2p::types::Seeding::DNSSeed, seeds: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 94127520585152, alloc: alloc::alloc::Global}, len: 94127520607512}}), capabilities: grin_p2p::types::Capabilities {bits: 15}, peers_allow: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 94127520585155, alloc: alloc::alloc::Global}, len: 94127520607512}}), peers_deny: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 3, alloc: alloc::alloc::Global}, len: 31}}), peers_preferred: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 3, alloc: alloc::alloc::Global}, len: 94127520585155}}), ban_window: <error reading variable>, peer_max_inbound_count: <error reading variable>, peer_max--Type <RET> for more, q to quit, c to continue without paging--
_outbound_count: <error reading variable>, peer_min_preferred_outbound_count: <error reading variable>, peer_listener_buffer_count: <error reading variable>, dandelion_peer: core::option::Option<grin_p2p::types::PeerAddr>::Some(grin_p2p::types::PeerAddr (<error reading variable>))}, pool_config: grin_pool::types::PoolConfig {accept_fee_base: 1000000, max_pool_size: 50000, max_stempool_size: 50000, mineable_max_weight: 40000}, dandelion_config: grin_pool::types::DandelionConfig {epoch_secs: 600, embargo_secs: 180, aggregation_secs: 30, stem_probability: 90, always_stem_our_txs: true}, stratum_mining_config: core::option::Option<grin_servers::common::types::StratumServerConfig>::Some(grin_servers::common::types::StratumServerConfig {enable_stratum_server: core::option::Option<bool>::Some(false), stratum_server_addr: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0520 "127.0.0.1:3416\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}), attempt_time_per_block: 15, minimum_share_difficulty: 1, wallet_listener_url: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0500 "http://127.0.0.1:3415\000", _marker: core::marker::PhantomData<u8>}, cap: 21, alloc: alloc::alloc::Global}, len: 21}}, burn_reward: false}), webhook_config: grin_servers::common::types::WebHooksConfig {tx_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 140722141972184, alloc: alloc::alloc::Global}, len: 140722141972152}}), header_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 140722141972189, alloc: alloc::alloc::Global}, len: 94127480997404}}), block_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 94127486617710, alloc: alloc::alloc::Global}, len: 140722141950368}}), block_accepted_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 140722141972128, alloc: alloc::alloc::Global}, len: 94127520613664}}), nthreads: 4, timeout: 10}}
#14 0x0000559bc313ca55 in grin::real_main () at src/bin/grin.rs:188
        logs_tx = core::option::Option<std::sync::mpsc::SyncSender<grin_util::logger::LogEntry>>::None
        logs_rx = core::option::Option<std::sync::mpsc::Receiver<grin_util::logger::LogEntry>>::None
        logging_config = grin_util::logger::LoggingConfig {log_to_stdout: true, stdout_log_level: log::Level::Warn, log_to_file: true, file_log_level: log::Level::Info, log_file_path: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56d3cf0 "\220\237mśU\000", _marker: core::marker::PhantomData<u8>}, cap: 38, alloc: alloc::alloc::Global}, len: 38}}, log_file_append: true, log_max_size: <error reading variable>, log_max_files: <error reading variable>, tui_running: core::option::Option<bool>::None}
        config = grin_config::types::GlobalConfig {config_file_path: core::option::Option<std::path::PathBuf>::Some(std::path::PathBuf {inner: std::ffi::os_str::OsString {inner: std::sys_common::os_str_bytes::Buf {inner: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56d5d10 ".grin/main/grin-server.toml\000", _marker: core::marker::PhantomData<u8>}, cap: 39, alloc: alloc::alloc::Global}, len: 39}}}}), members: core::option::Option<grin_config::types::ConfigMembers>::Some(grin_config::types::ConfigMembers {server: grin_servers::common::types::ServerConfig {db_root: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56dad10 "\001\000", _marker: core::marker::PhantomData<u8>}, cap: 33, alloc: alloc::alloc::Global}, len: 33}}, api_http_addr: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0500 "http://127.0.0.1:3415\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}, api_secret_path: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56da600 ".grin/main/.api_secret\000", _marker: core::marker::PhantomData<u8>}, cap: 34, alloc: alloc::alloc::Global}, len: 34}}), foreign_api_secret_path: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::un--Type <RET> for more, q to quit, c to continue without paging--
ique::Unique<u8> {pointer: 0x559bc56e0520 "127.0.0.1:3416\000", _marker: core::marker::PhantomData<u8>}, cap: 19, alloc: alloc::alloc::Global}, len: 19}}), tls_certificate_file: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 20, alloc: alloc::alloc::Global}, len: 1}}), tls_certificate_key: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 94127500765240, alloc: alloc::alloc::Global}, len: 140722141948720}}), chain_type: grin_core::global::ChainTypes::Mainnet, chain_validation_mode: grin_servers::common::types::ChainValidationMode::Disabled, archive_mode: core::option::Option<bool>::Some(false), skip_sync_wait: core::option::Option<bool>::Some(false), run_tui: core::option::Option<bool>::Some(false), run_test_miner: core::option::Option<bool>::Some(false), test_miner_wallet_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 19, alloc: alloc::alloc::Global}, len: 94127506083895}}), p2p_config: grin_p2p::types::P2PConfig {host: <error reading variable>, port: 3414, seeding_type: grin_p2p::types::Seeding::DNSSeed, seeds: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 1, alloc: alloc::alloc::Global}, len: 94127520570640}}), capabilities: grin_p2p::types::Capabilities {bits: 15}, peers_allow: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 1, alloc: alloc::alloc::Global}, len: 94127520570640}}), peers_deny: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 94127520570640, alloc: alloc::alloc::Global}, len: 39}}), peers_preferred: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 1, alloc: alloc::alloc::Global}, len: 140722141950608}}), ban_window: <error reading variable>, peer_max_inbound_count: <error reading variable>, peer_max_outbound_count: <error reading variable>, peer_min_preferred_outbound_count: <error reading variable>, peer_listener_buffer_count: <error reading variable>, dandelion_peer: core::option::Option<grin_p2p::types::PeerAddr>::Some(grin_p2p::types::PeerAddr (<error reading variable>))}, pool_config: grin_pool::types::PoolConfig {accept_fee_base: 1000000, max_pool_size: 50000, max_stempool_size: 50000, mineable_max_weight: 40000}, dandelion_config: grin_pool::types::DandelionConfig {epoch_secs: 600, embargo_secs: 180, aggregation_secs: 30, stem_probability: 90, always_stem_our_txs: true}, stratum_mining_config: core::option::Option<grin_servers::common::types::StratumServerConfig>::Some(grin_servers::common::types::StratumServerConfig {enable_stratum_server: core::option::Option<bool>::Some(false), stratum_server_addr: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0c10 ".foreign_api_secretace\nf!\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}), attempt_time_per_block: 15, minimum_share_difficulty: 1, wallet_listener_url: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0bf0 "127.0.0.1:3413\000", _marker: core::marker::PhantomData<u8>}, cap: 21, alloc: alloc::alloc::Global}, len: 21}}, burn_reward: false}), webhook_config: grin_servers::common::types::WebHooksConfig {tx_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 140722141956104, alloc: alloc::alloc::Global}, len: 140722141956072}}), header_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 140722141956109, alloc: alloc::alloc::Global}, len: 94127480997404}}), block_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec:--Type <RET> for more, q to quit, c to continue without paging--
:RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 94127486617710, alloc: alloc::alloc::Global}, len: 140722141950336}}), block_accepted_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 140722141956048, alloc: alloc::alloc::Global}, len: 94127520615440}}), nthreads: 4, timeout: 10}}, logging: core::option::Option<grin_util::logger::LoggingConfig>::Some(grin_util::logger::LoggingConfig {log_to_stdout: true, stdout_log_level: log::Level::Warn, log_to_file: true, file_log_level: log::Level::Info, log_file_path: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e05d0 "\001\000", _marker: core::marker::PhantomData<u8>}, cap: 38, alloc: alloc::alloc::Global}, len: 38}}, log_file_append: true, log_max_size: <error reading variable>, log_max_files: <error reading variable>, tui_running: core::option::Option<bool>::Some(2)})})}
        chain_type = grin_core::global::ChainTypes::Mainnet
        node_config = core::option::Option<grin_config::types::GlobalConfig>::Some(grin_config::types::GlobalConfig {config_file_path: core::option::Option<std::path::PathBuf>::Some(std::path::PathBuf {inner: std::ffi::os_str::OsString {inner: std::sys_common::os_str_bytes::Buf {inner: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56d9530 ".grin/main/grin-server.toml\000", _marker: core::marker::PhantomData<u8>}, cap: 39, alloc: alloc::alloc::Global}, len: 39}}}}), members: core::option::Option<grin_config::types::ConfigMembers>::Some(grin_config::types::ConfigMembers {server: grin_servers::common::types::ServerConfig {db_root: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0600 ".grin/main/chain_data\nattempq\000", _marker: core::marker::PhantomData<u8>}, cap: 33, alloc: alloc::alloc::Global}, len: 33}}, api_http_addr: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0c30 "127.0.0.1:3413\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}, api_secret_path: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56dbb30 ".grin/main/.api_secret\000", _marker: core::marker::PhantomData<u8>}, cap: 34, alloc: alloc::alloc::Global}, len: 34}}), foreign_api_secret_path: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0c50 ".foreign_api_secretme/ma!\000", _marker: core::marker::PhantomData<u8>}, cap: 19, alloc: alloc::alloc::Global}, len: 19}}), tls_certificate_file: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), tls_certificate_key: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), chain_type: grin_core::global::ChainTypes::Mainnet, chain_validation_mode: grin_servers::common::types::ChainValidationMode::Disabled, archive_mode: core::option::Option<bool>::Some(false), skip_sync_wait: core::option::Option<bool>::Some(false), run_tui: core::option::Option<bool>::Some(false), run_test_miner: core::option::Option<bool>::Some(false), test_miner_wallet_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), p2p_config: grin_p2p::types::P2PConfig {host: <error reading variable>, port: 3414, seeding_type: grin_p2p::types::Seeding::DNSSeed, seeds: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 3, alloc: alloc::alloc::Global}, len: 94127520602400}}), capabilities: grin_p2p::types::Capabilities {bits: 15}, peers_allow: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 3, alloc: alloc::alloc::Global}, len: 94127520602400}}), peers_deny: core::option::Option<grin_p2p::msg::PeerAddrs>::--Type <RET> for more, q to quit, c to continue without paging--
Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 3, alloc: alloc::alloc::Global}, len: 94127520602400}}), peers_preferred: core::option::Option<grin_p2p::msg::PeerAddrs>::Some(grin_p2p::msg::PeerAddrs {peers: alloc::vec::Vec<grin_p2p::types::PeerAddr> {buf: alloc::raw_vec::RawVec<grin_p2p::types::PeerAddr, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<grin_p2p::types::PeerAddr> {pointer: 0x0, _marker: core::marker::PhantomData<grin_p2p::types::PeerAddr>}, cap: 3, alloc: alloc::alloc::Global}, len: 94127520602400}}), ban_window: <error reading variable>, peer_max_inbound_count: <error reading variable>, peer_max_outbound_count: <error reading variable>, peer_min_preferred_outbound_count: <error reading variable>, peer_listener_buffer_count: <error reading variable>, dandelion_peer: core::option::Option<grin_p2p::types::PeerAddr>::Some(grin_p2p::types::PeerAddr (<error reading variable>))}, pool_config: grin_pool::types::PoolConfig {accept_fee_base: 1000000, max_pool_size: 50000, max_stempool_size: 50000, mineable_max_weight: 40000}, dandelion_config: grin_pool::types::DandelionConfig {epoch_secs: 600, embargo_secs: 180, aggregation_secs: 30, stem_probability: 90, always_stem_our_txs: true}, stratum_mining_config: core::option::Option<grin_servers::common::types::StratumServerConfig>::Some(grin_servers::common::types::StratumServerConfig {enable_stratum_server: core::option::Option<bool>::Some(false), stratum_server_addr: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0c70 "127.0.0.1:3416\000", _marker: core::marker::PhantomData<u8>}, cap: 14, alloc: alloc::alloc::Global}, len: 14}}), attempt_time_per_block: 15, minimum_share_difficulty: 1, wallet_listener_url: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56e0c90 "http://127.0.0.1:3415g fa\000", _marker: core::marker::PhantomData<u8>}, cap: 21, alloc: alloc::alloc::Global}, len: 21}}, burn_reward: false}), webhook_config: grin_servers::common::types::WebHooksConfig {tx_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), header_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), block_received_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), block_accepted_url: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x0, _marker: core::marker::PhantomData<u8>}, cap: 2, alloc: alloc::alloc::Global}, len: 94127520611120}}), nthreads: 4, timeout: 10}}, logging: core::option::Option<grin_util::logger::LoggingConfig>::Some(grin_util::logger::LoggingConfig {log_to_stdout: true, stdout_log_level: log::Level::Warn, log_to_file: true, file_log_level: log::Level::Info, log_file_path: alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56d3a30 ".grin/main/grin-server.log\000", _marker: core::marker::PhantomData<u8>}, cap: 38, alloc: alloc::alloc::Global}, len: 38}}, log_file_append: true, log_max_size: <error reading variable>, log_max_files: <error reading variable>, tui_running: core::option::Option<bool>::Some(2)})})})
        args = clap::args::arg_matches::ArgMatches {args: std::collections::hash::map::HashMap<&str, clap::args::matched_arg::MatchedArg, std::collections::hash::map::RandomState> {base: hashbrown::map::HashMap<&str, clap::args::matched_arg::MatchedArg, std::collections::hash::map::RandomState> {hash_builder: std::collections::hash::map::RandomState {k0: 9983641536333455924, k1: 6925433874672789264}, table: hashbrown::raw::RawTable<(&str, clap::args::matched_arg::MatchedArg)> {bucket_mask: 0, ctrl: core::ptr::non_null::NonNull<u8> {pointer: 0x559bc49f6480 <hashbrown::raw::sse2::Group::static_empty::ALIGNED_BYTES> '\377' <repeats 16 times>, "\001\000"}, data: core::ptr::non_null::NonNull<(&str, clap::args::matched_arg::MatchedArg)> {pointer: 0x8}, growth_left: 0, items: 0, marker: core::marker::PhantomData<(&str, clap::args::matched_arg::MatchedArg)>}}}, subcommand: core::option::Option<alloc::boxed::Box<clap::args::subcommand::SubCommand>>::Some(0x0), usage: core::option::Option<alloc::string::String>::Some(alloc::string::String {vec: alloc::vec::Vec<u8> {buf: alloc::raw_vec::RawVec<u8, alloc::alloc::Global> {ptr: core::ptr::unique::Unique<u8> {pointer: 0x559bc56d4290 "USAGE:\n    grin [FLAGS] [SUBCOMMAND]\000", _marker: core::marker::PhantomData<u8>}, cap: 7
, alloc: alloc::alloc::Global}, len: 36}})}
        yml = 0x559bc56d9930
#15 0x0000559bc313b596 in grin::main () at src/bin/grin.rs:72
```
