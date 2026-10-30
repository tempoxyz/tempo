#!/bin/sh
# Creates the zone on L1 the operator way, with three sequencers and a 2-of-3 settlement
# threshold (the first is the initial leader), registers the deposit encryption key, and
# writes everything the zone nodes need to /shared. Does nothing once /shared/provisioned
# exists.
#
# Keys are fixed and public, never real funds. The sequencers are dev accounts 5, 6 and 7
# of the "test ... junk" mnemonic, funded in the L1 genesis so they pay their own settlement
# gas. Dev account 0 owns the ZoneFactory and administers the portal. Node 0's sequencer key
# is the deposit encryption key; nodes 1 and 2 load it as an extra decryption key.
set -eu

S=/shared
L1_HTTP=http://10.20.0.10:8545

[ -f "$S/provisioned" ] && { echo "provision: already provisioned"; exit 0; }

DEV0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
SEQ_KEYS="0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba 0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
SEQ_ADDRS="0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc 0x976EA74026E726554dB657fA54763abd0C3a0aa9 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"
# Ed25519 P2P identities: zone-0, zone-1, zone-2, then zone-rpc.
P2P_KEYS="0x1111111111111111111111111111111111111111111111111111111111111111 0x2222222222222222222222222222222222222222222222222222222222222222 0x3333333333333333333333333333333333333333333333333333333333333333 0x4444444444444444444444444444444444444444444444444444444444444444"
P2P_PUBS="0xd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737 0xa09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0 0x17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce 0xd759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48"

nth() { echo "$2" | tr ' ' '\n' | sed -n "$(($1 + 1))p"; }

until cast block-number --rpc-url "$L1_HTTP" >/dev/null 2>&1; do sleep 1; done

rm -rf "$S/xtask"
seqs=""
for a in $SEQ_ADDRS; do seqs="$seqs --sequencer $a"; done
# shellcheck disable=SC2086
ZONE_FACTORY_OWNER_KEY=$DEV0 tempo-zone-xtask create-zone --output "$S/xtask" \
    --l1-rpc-url "$L1_HTTP" --zone-factory 0x5aF2000000000000000000000000000000000000 \
    $seqs --threshold 2 --admin "$ADMIN" --rpc-url http://10.20.0.20:8545
portal=$(jq -r .portal "$S/xtask/zone.json")
echo "provision: portal $portal"

PRIVATE_KEY=$(nth 0 "$SEQ_KEYS") tempo-zone-xtask set-encryption-key \
    --l1-rpc-url "$L1_HTTP" --portal "$portal"

cp "$S/xtask/genesis.json" "$S/genesis.json"
cp "$S/xtask/zone.json" "$S/zone.json"
nth 0 "$SEQ_KEYS" > "$S/decryption.keys"
for i in 0 1 2; do
    nth "$i" "$SEQ_KEYS" > "$S/seq-$i.key"
    nth "$i" "$P2P_KEYS" > "$S/p2p-$i.key"
done
nth 3 "$P2P_KEYS" > "$S/p2p-rpc.key"

{
    echo "leader_ed25519_public_key = \"$(nth 0 "$P2P_PUBS")\""
    for i in 0 1 2; do
        echo ""
        echo "[[nodes]]"
        echo "name = \"zone-$i\""
        echo "ed25519_public_key = \"$(nth "$i" "$P2P_PUBS")\""
        echo "secp256k1_address = \"$(nth "$i" "$SEQ_ADDRS")\""
        echo "address = \"10.20.0.$((11 + i)):9200\""
    done
    echo ""
    echo "[[nodes]]"
    echo "name = \"zone-rpc\""
    echo "ed25519_public_key = \"$(nth 3 "$P2P_PUBS")\""
    echo "address = \"10.20.0.20:9200\""
    echo "rpc_only = true"
} > "$S/manifest.toml"

touch "$S/provisioned"
echo "provision: done"
