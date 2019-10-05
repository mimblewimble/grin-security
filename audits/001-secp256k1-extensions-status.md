# 001 - secp256k1 Extensions Audit

_This document tracks the status of issues raised during audit of Grin’s secp256k1 extensions by Jean-Philippe Aumasson._

| ID | Description | Status |
|---|---|---|
| 2.1 | Optimized out dead assignment may leak sensitive data | _No changes due to impossibility of enforcing this compiler-side. Binary still needs to be reviewed manually._ |
| 2.2 | Missing null pointers checks   | _Addressed by_ https://github.com/mimblewimble/secp256k1-zkp/pull/37 |
| 3.1 | Unfreed heap allocations | _Addressed by_ https://github.com/mimblewimble/secp256k1-zkp/pull/37 |
| 3.2 | Unchecked heap allocation | _Addressed by_ https://github.com/mimblewimble/secp256k1-zkp/pull/37 _but still room for improvement for NULL checking in_ `secp256k1_aggsig_build_scratch_and_verify()`. |
| 3.3 | `secp256k1_compute_sighash_single()` always returns `1` with `scalar_low_impl.h` | _Addressed by_ https://github.com/mimblewimble/secp256k1-zkp/pull/37 |
| 3.4 | Unnecessary operations | _Should be a non-issue. See comments regarding short circuiting behaviour in_ https://github.com/mimblewimble/secp256k1-zkp/pull/37 |
| 3.5 | Unnecessary operation | _Addressed by_ https://github.com/mimblewimble/secp256k1-zkp/pull/37 |
| 3.6 | Faster rejection of invalid parameters | _Non-issue, early nbit parameter check already exists_ |
