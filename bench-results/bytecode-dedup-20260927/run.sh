#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
base=https://huggingface.co/datasets/Zellic/all-ethereum-contracts/resolve/30510b58af8084b8a5b9ddfa148a46ae24132b16
for name in bytecodes contracts; do
  if [[ ! -f "$name.zip" ]]; then
    curl --fail --location --retry 3 --max-time 900 --output "$name.zip.part" "$base/$name.zip?download=true"
    mv "$name.zip.part" "$name.zip"
  fi
done
sha256sum --check expected-input-checksums.txt
g++ -std=c++17 -O2 -Wall -Wextra -Werror analyze.cpp -o analyze
node test.cjs
stream_csv() {
  python3 -c 'import shutil, sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); shutil.copyfileobj(z.open(sys.argv[2]), sys.stdout.buffer, 1024 * 1024)' "$1" "$2"
}
if [[ ! -f code-lengths.tsv ]]; then
  stream_csv bytecodes.zip bytecodes.csv | nice -n 10 ./analyze lengths > code-lengths.tsv.part
  mv code-lengths.tsv.part code-lengths.tsv
fi
stream_csv contracts.zip contracts.csv | nice -n 10 ./analyze references code-lengths.tsv > summary.json.part
mv summary.json.part summary.json
jq -e '.contract_rows == 69788231 and .all_code_hashes == 1539859 and .maximum_deployment_block <= 21850000' summary.json > /dev/null
sha256sum bytecodes.zip contracts.zip code-lengths.tsv > checksums.txt
date -u +%FT%TZ
jq '{contract_rows,all_code_hashes,deduplicated_referenced_bytes,without_deduplication_bytes,saved_percent,expansion_factor}' summary.json
