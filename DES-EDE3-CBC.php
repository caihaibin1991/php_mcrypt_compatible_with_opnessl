<?php
class Crypt3Des {
	public $key = "";
	public $iv = "12345678";
	function __construct($key) {
		$this->key = $key;
	}
	// ����
	public function encrypt($input) {
		if (! extension_loaded ( 'mcrypt' )) {
			return $this->ops_encrypt ( $input );
		}
		$size = mcrypt_get_block_size ( 'tripledes', 'cbc' );
		$input = $this->pkcs5_pad ( $input, $size ); // pkcs5��䷽ʽ
		
		$td = mcrypt_module_open ( MCRYPT_3DES, '', MCRYPT_MODE_CBC, '' );
		// ʹ��MCRYPT_3DES�㷨,cbcģʽ
		mcrypt_generic_init ( $td, $this->key, $this->iv );
		// ��ʼ����
		$data = mcrypt_generic ( $td, $input );
		// ����
		mcrypt_generic_deinit ( $td );
		// ����
		mcrypt_module_close ( $td );
		// $data = $this->removeBR(base64_encode($data));
		$data = $this->removeBR ( $data );
		return bin2hex ( $data );
	}
	
	// ����
	public function decrypt($encrypted) {
		if (! extension_loaded ( 'mcrypt' )) {
			return $this->ops_decrypt ( $encrypted );
		}
		$encrypted = pack ( 'H*', $encrypted );
		
		$td = mcrypt_module_open ( MCRYPT_3DES, '', MCRYPT_MODE_CBC, '' );
		// ʹ��MCRYPT_3DES�㷨,cbcģʽ
		mcrypt_generic_init ( $td, $this->key, $this->iv );
		// ��ʼ����
		$decrypted = mdecrypt_generic ( $td, $encrypted );
		// ����
		mcrypt_generic_deinit ( $td );
		// ����
		mcrypt_module_close ( $td );
		$decrypted = $this->pkcs5_unpad ( $decrypted ); // pkcs5��䷽ʽ
		return $decrypted;
	}
	
	// ɾ���س��ͻ���
	public function removeBR($str) {
		$len = strlen ( $str );
		$newstr = "";
		$str = str_split ( $str );
		for($i = 0; $i < $len; $i ++) {
			if ($str [$i] != '\n' and $str [$i] != '\r') {
				$newstr .= $str [$i];
			}
		}
		
		return $newstr;
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
		$encrypted = openssl_encrypt ( $str, 'DES-EDE3-CBC', $this->key, false, $this->iv );
		return bin2hex ( base64_decode ( $encrypted ) );
	}
	/**
	 * openssl 兼容处理方式,如果出现兼容问题.直接切换函数测试或覆盖代码.
	 */
	function ops_decrypt($cipher) {
		$cipher = hex2bin ( $cipher );
		$iv = $this->iv;
		$decrypted = openssl_decrypt ( $cipher, 'DES-EDE3-CBC', $this->key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $this->iv );
		return $this->pkcs5_unpad ( $decrypted );
	}
	function show_error() {
		while ( $msg = openssl_error_string () ) {
			echo $msg . "<br />\n";
		}
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
}
