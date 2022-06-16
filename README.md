# Secure PHP Forward Shell

This project was inspired by ippsec's [forward-shell method](https://github.com/IppSec/forward-shell).

This project uses RSA signing and AES encryption to secure the communications between the server and the client.

Forward-shell is able to bypass firewalls that block reverse/bind shells.

## Installation

This project depends on libraries below:
```
pycryptodome
pyOpenSSL
requests
```

You can install this project by:
```
git clone https://github.com/CanOzSec/secure-forward-shell.git
pip install -r requirements.txt
```

If you have any problems with installation you can try using a python virtual environment by:
```
python3 -m venv secure-forward-shell

cd secure-forward-shell

source bin/activate

git clone https://github.com/CanOzSec/secure-forward-shell.git

cd secure-forward-shell

pip install -r requirements.txt
```

## Usage

In order to use this shell you need to configure both backdoor.php and client.py according to your needs.

For basic usage just run
```
chmod +x ./generate.sh && ./generate.sh
```
and copy and paste given values to according fields in both client.py and backdoor.php.
After that you can upload this php to your target and change the URL in client.py accordingly.
```
python3 client.py
```

## Notes

Client doesn't automatically upgrade your shell to tty because every environment is different and doing it manually is often more reliable.
