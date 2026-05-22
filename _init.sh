#!/bin/bash
cd "$(dirname "$0")" || exit
source ./.env/bin/activate
exec python upd.py --init-db
