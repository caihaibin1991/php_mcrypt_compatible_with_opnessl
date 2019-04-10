<?php
class CryptDesMobile {
	public $iv = 'fedcba9876543210'; // ame as in JAVA
	public $key = '0123456789abcdef'; // ame as in JAVA
	function __construct($key = '') {
		if ($key)
			$this->key = $key;
	}
	function setKey($key) {
		if ($key)
			$this->key = $key;
	}
	function setIv($iv) {
		if ($iv)
			$this->iv = $iv;
	}
	function encrypt($str) {
		if (! extension_loaded ( 'mcrypt' )) {
			return $this->ops_encrypt ( $str );
		}
		// $key = $this->hex2bin($key);
		$iv = $this->iv;
		
		$td = mcrypt_module_open ( MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, $iv );
		
		mcrypt_generic_init ( $td, $this->key, $iv );
		$encrypted = mcrypt_generic ( $td, $str );
		
		mcrypt_generic_deinit ( $td );
		mcrypt_module_close ( $td );
		
		return bin2hex ( $encrypted );
	}
	function decrypt($code) {
		if (! extension_loaded ( 'mcrypt' )) {
			return $this->ops_decrypt ( $code );
		}
		// $key = $this->hex2bin($key);
		$code = $this->hex2bin ( $code );
		$iv = $this->iv;
		
		$td = mcrypt_module_open ( MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, $iv );
		
		mcrypt_generic_init ( $td, $this->key, $iv );
		$decrypted = mdecrypt_generic ( $td, $code );
		
		mcrypt_generic_deinit ( $td );
		mcrypt_module_close ( $td );
		return $this->pkcs5_unpad ( $decrypted );
	}
	/**
	 * openssl 兼容处理方式,如果出现兼容问题.直接切换函数测试或覆盖代码.
	 */
	function ops_encrypt($str) {
		// 非OPENSSL_RAW_DATA | OPENSSL_NO_PADDING 形式,返回base64加密后的二进制数据.
		// 且默认尾部会自动补充上填充值,正常解析,需要进行pkcs5_unpad填充值去除
		// 如果使用上面的参数,则会要求传入参数前,进行位填充.否则openssl_error_string会报错
		// 异常:digital envelope routine: EVP_DecryptFinal_ex:wrong final block length
		// (没有按照指定块填充,传入参数必须是最小块的倍数)
		$encrypted = openssl_encrypt ( $str, 'AES-128-CBC', $this->key, false, $this->iv );
		return bin2hex ( base64_decode ( $encrypted ) );
	}
	function show_error() {
		while ( $msg = openssl_error_string () ) {
			echo $msg . "<br />\n";
		}
	}
	/**
	 * openssl 兼容处理方式,如果出现兼容问题.直接切换函数测试或覆盖代码.
	 */
	function ops_decrypt($cipher) {
		// $key = $this->hex2bin($key);
		$cipher = $this->hex2bin ( $cipher );
		$iv = $this->iv;
		$decrypted = openssl_decrypt ( $cipher, 'AES-128-CBC', $this->key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $this->iv );
		return $this->pkcs5_unpad ( $decrypted );
	}
	public function pkcs5_pad($text, $blocksize) {
		$pad = $blocksize - (mb_strlen ( $text, "8bit" ) % $blocksize);
		return $text . str_repeat ( chr ( $pad ), $pad );
	}
	public function pkcs5_unpad($text) {
		$text_len = mb_strlen ( $text, "8bit" );
		$pad = ord ( $text {$text_len - 1} );
		// openssl 默认自动填充,后面有一定概率都是00000.
		if ($text_len && ! $pad) {
			return trim ( $text );
		}
		if ($pad > $text_len) {
			return false;
		}
		if (strspn ( $text, chr ( $pad ), $text_len - $pad ) != $pad) {
			return false;
		}
		return mb_substr ( $text, 0, - 1 * $pad, "8bit" );
	}
	function pad2Length($text, $padlen) {
		$len = strlen ( $text ) % $padlen;
		$res = $text;
		$span = $padlen - $len;
		for($i = 0; $i < $span; $i ++) {
			$res .= chr ( $span );
		}
		return $res;
	}
	function hex2bin($hexdata) {
		$bindata = '';
		
		for($i = 0; $i < strlen ( $hexdata ); $i += 2) {
			$bindata .= chr ( hexdec ( substr ( $hexdata, $i, 2 ) ) );
		}
		
		return $bindata;
	}
}
