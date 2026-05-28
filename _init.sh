#!/bin/bash
cd "$(dirname "$0")" || exit
source ./.env/bin/activate
exec python gateway.py --init-db
