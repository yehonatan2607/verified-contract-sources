# Contract archive catalog

Initial capture: 2 November 2026

This catalog records the initial bounded import from the official Immunefi public bounty catalog. Each archived contract has a dedicated branch containing public verified source and capture metadata.

| Immunefi program | Archived | Recognized explorer contracts | Smart-contract scope entries |
| --- | ---: | ---: | ---: |
| [AAVE](https://immunefi.com/bug-bounty/aave/) | 3 | 3 | 83 |
| [Aevo](https://immunefi.com/bug-bounty/Aevo/) | 2 | 2 | 2 |
| [Ankr](https://immunefi.com/bug-bounty/ankr/) | 1 | 3 | 6 |
| [Ante Finance](https://immunefi.com/bug-bounty/antefinance/) | 7 | 7 | 7 |
| [Beefy Finance](https://immunefi.com/bug-bounty/beefyfinance/) | 175 | 240 | 243 |
| [Boba Network](https://immunefi.com/bug-bounty/bobanetwork/) | 3 | 3 | 5 |
| [DAWN USD.infra Vault](https://immunefi.com/bug-bounty/dawn/) | 2 | 2 | 5 |
| [DeXe Protocol](https://immunefi.com/bug-bounty/dexeprotocol/) | 8 | 10 | 11 |
| [dHEDGE](https://immunefi.com/bug-bounty/dhedge/) | 5 | 5 | 7 |
| [Gamma](https://immunefi.com/bug-bounty/gamma/) | 3 | 3 | 3 |
| [Hashflow](https://immunefi.com/bug-bounty/hashflow/) | 4 | 4 | 4 |
| [Ichi](https://immunefi.com/bug-bounty/ichi/) | 4 | 4 | 5 |
| [Immunefi](https://immunefi.com/bug-bounty/immunefi/) | 2 | 2 | 3 |
| [Immutable](https://immunefi.com/bug-bounty/immutable/) | 4 | 4 | 10 |
| [LayerZero](https://immunefi.com/bug-bounty/layerzero/) | 3 | 3 | 11 |
| [Money on Chain / RIF on Chain](https://immunefi.com/bug-bounty/moneyonchain/) | 36 | 53 | 55 |
| [Polygon](https://immunefi.com/bug-bounty/polygon/) | 3 | 4 | 8 |
| [RootstockLabs](https://immunefi.com/bug-bounty/rootstocklabs/) | 8 | 8 | 10 |
| [Stargate](https://immunefi.com/bug-bounty/stargate/) | 1 | 2 | 5 |
| [Synthetix](https://immunefi.com/bug-bounty/synthetix/) | 3 | 3 | 3 |
| [Utix](https://immunefi.com/bug-bounty/utix/) | 1 | 1 | 1 |
| [Xterio](https://immunefi.com/bug-bounty/xterio/) | 1 | 1 | 1 |
| **Total** | **279** | **367** | **488** |

"Recognized explorer contracts" are scope entries whose explorer and chain are supported by the keyless capture pipeline. "Archived" means the complete source bundle passed the configured verification, proxy-resolution, path, file-count, and size boundaries.

No empty or knowingly incomplete branch is created. The remaining entries are explicit coverage gaps, including unsupported explorer types, unavailable verified source, unresolved proxy implementations, unsafe or empty provider files, and bounded source responses. Beets currently uses an unsupported explorer, and both recognized SSV Network sources exceed the current provider response limit, so neither program is included in the 22-program archived total.
