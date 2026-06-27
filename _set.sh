#!/bin/bash
cd "$(dirname "$0")" || exit
python3 -m venv venv
#sudo chmod +x .venv/bin/activate
source venv/bin/activate
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
source gen_cert.sh
