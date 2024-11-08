Instead of using the more standard P2PKH nowadays, Satoshi originally used P2PK, with this scriptPubKey:

```
OP_PUSHBYTES_65
04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
OP_CHECKSIG
```

See UTXO `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0` in block #0.

```console
❯ cargo run -r --bin satoshi-address | tee log
# <omitted>
❯ cat log | rg '^1'
1 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0
1 08901b81e39bc61d632c93241c44ec3763366bd57444b01494481ed46079c898:0
1 b338282600dcb99fcf112159b2504e179d343691fc70d1882b3721d0a7664b5c:0
1 f59c0ea559a4a22933ea2d71224002b5a60dcc885351ce67c58ba0bb0a53df49:0
1 dfe1986a5392f7ffa82d95caac650dba064237871b8600c0a99ec86fd0f96443:0
1 2cc7cd85d75b113fa8bf4d80aded938ab261bae8ce1b85afe066e84024276d9b:0
```

If searching all Satoshi P2PK transaction outputs in the blockchain, we can only find these six, with their timestamps (
UTC+8):

```
- 2009-01-04 02:15:05
- 2012-03-21 18:14:21
- 2023-07-28 12:51:04
- 2023-12-16 00:26:08
- 2023-12-16 04:18:37
- 2024-05-22 15:13:18
```

Statistics:

```console
❯ cat log | rg '^1' | wc -l
6
❯ cat log | rg '^2' | wc -l
45778
```

I made the same P2PK transaction on
testnet4: https://mempool.space/testnet4/tx/448a9298619823fd12560ad7d34406e4aeb44556cbf608aaa3bf38ca9876cf3a#vout=1
