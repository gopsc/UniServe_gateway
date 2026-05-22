cd $PSScriptRoot
python -m venv .env
. .env\Scripts\Activate.ps1
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
bash gen_cert.sh