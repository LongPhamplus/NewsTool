#!/usr/bin/env bash
# Encrypt/decrypt local secrets with SOPS + age. Plain files (.env, config.yaml) stay gitignored;
# only the encrypted copies (.env.enc, config.enc.yaml) are committed.
set -euo pipefail
cd "$(dirname "$0")"
export SOPS_DISABLE_VERSION_CHECK=1

case "${1:-}" in
  decrypt)
    umask 077
    sops decrypt --input-type dotenv --output-type dotenv .env.enc > .env.new
    sops decrypt --input-type yaml --output-type binary config.enc.yaml > config.yaml.new
    for f in .env config.yaml; do
      # Never silently lose local edits that were not encrypted yet.
      if [ -f "$f" ] && ! cmp -s "$f" "$f.new"; then cp -p "$f" "$f.bak"; echo "  $f khác bản mã hóa -> đã lưu $f.bak"; fi
      mv "$f.new" "$f"
    done
    echo "Đã giải mã -> .env, config.yaml" ;;
  encrypt)
    sops encrypt --input-type dotenv --output-type dotenv --filename-override .env.enc .env > .env.enc
    sops encrypt --input-type binary --output-type yaml --filename-override config.enc.yaml config.yaml > config.enc.yaml
    echo "Đã mã hóa -> .env.enc, config.enc.yaml (nhớ commit)" ;;
  updatekeys)
    sops updatekeys --input-type dotenv -y .env.enc
    sops updatekeys -y config.enc.yaml ;;
  *)
    echo "Dùng: ./secrets.sh decrypt | encrypt | updatekeys" >&2; exit 1 ;;
esac
