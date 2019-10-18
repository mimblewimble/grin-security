# 001 - Grin 2019 Audit

_This document tracks the status of issues raised during the 2019 audit of Grin by Coinspect._

| ID | Description | Status |
|---|---|---|
| 001 | Remote file system write access and code execution during TxHashSet processing | _Addressed by_ https://github.com/mimblewimble/grin/pull/2624 |
| 002 | PMMR panic after processing an invalid TxHashSet leaves node unable to sync   | _Addressed by_ https://github.com/mimblewimble/grin/pull/2621 |
| 003 | zip-rs library panic and corrupted storage during TxHashSet processing results in node unable to sync | _Addressed by_ https://github.com/mimblewimble/grin/pull/2908 |
| 004 | CRoaring: memory corruption and DoS while processing bitmaps | _Addressed by_ https://github.com/mimblewimble/grin/pull/2763 |
| 005 | prune_list panic after processing an invalid TxHashSet leaves node unable to sync and restart | _Addressed by_ https://github.com/mimblewimble/grin/pull/2976 |
| 006 | Disk space DoS via TxHashSetRequest p2p messages | _Addressed by_ https://github.com/mimblewimble/grin/pull/2575 |
| 007 | Nodes can be indefinitely prevented from synchronizing the blockchain via unsolicited TxHashSetArchive p2p messages | _Addressed by_ https://github.com/mimblewimble/grin/pull/2984 |
| 008 | Insecure file handling local privilege escalation | _Addressed by_ https://github.com/mimblewimble/grin/pull/2753 |
| 009 | Nodes can be tricked into banning well-behaved peers (temporary file shared among peer threads) | _Addressed by_ https://github.com/mimblewimble/grin/pull/2753 |
| 010 | Node crashes when ulimit is reached with many incoming peer connections | _Addressed by_ https://github.com/mimblewimble/grin/pull/2985 |
| 011 | High CPU usage when handling many incoming peer connections results in stuck miner and unresponsive node | _Addressed by_ https://github.com/mimblewimble/grin/pull/2985 |
| 012 | Miner thread panic after long chain reorganization | _Addressed by_ https://github.com/mimblewimble/grin/pull/2988 |
| 013 | Arbitrary orphan blocks can be used to flush out legitimate ones from the OrphanBlockPool | _Addressed by_ https://github.com/mimblewimble/grin/pull/2981 |
| 014 | Known headers replay can be abused to clog victim node CPU with PoW computations | _Addressed by_ https://github.com/mimblewimble/grin/pull/2834 |
