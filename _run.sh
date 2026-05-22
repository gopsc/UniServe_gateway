#!/bin/bash
cd "$(dirname "$0")" || exit
source ./.env/bin/activate
# 直接运行Python应用，HTTPS/HTTP配置在app.py中处理
exec python upd.py 1>/dev/null
