#!/bin/bash
cd "$(dirname "$0")" || exit
source ./venv/bin/activate
exec python gateway.py --init-db
