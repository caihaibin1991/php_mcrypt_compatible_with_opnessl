<?php
class DES {
	var $key;
	function __construct($key) {
		$this->key = $key;
	}
	function encrypt($input) {
		if (! extension_loaded ( 'mcrypt' )) {
			return $this->ops_encrypt ( $input );
		}
		$size = mcrypt_get_block_size ( 'des', 'ecb' );
		$input = $this->pkcs5_pad ( $input, $size );
		$key = $this->key;
		// ecb 模式下没有意义
		$td = mcrypt_module_open ( 'des', '', 'ecb', '' );
		$iv = @mcrypt_create_iv ( mcrypt_enc_get_iv_size ( $td ), MCRYPT_RAND );
		@mcrypt_generic_init ( $td, $key, $iv );
		$data = mcrypt_generic ( $td, $input );
		mcrypt_generic_deinit ( $td );
		mcrypt_module_close ( $td );
		$data = bin2hex ( $data );
		return $data;
	}
	function decrypt($encrypted) {
		if (! extension_loaded ( 'mcrypt' )) {
			return $this->ops_decrypt ( $encrypted );
		}
		$encrypted = pack ( 'H*', $encrypted );
		$key = $this->key;
		$td = mcrypt_module_open ( 'des', '', 'ecb', '' );
		// 使用MCRYPT_DES算法,cbc模式
		// $size = mcrypt_get_block_size ( MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC );
		$iv = @mcrypt_create_iv ( mcrypt_enc_get_iv_size ( $td ), MCRYPT_RAND );
		
		$iv = openssl_random_pseudo_bytes ( 8 );
		// $ks = mcrypt_enc_get_key_size ( $td );
		// The IV should normally have the size of the algorithms block size,
		// but you must obtain the size by calling mcrypt_enc_get_iv_size.
		// IV is ignored in ECB. IV MUST exist in CFB, CBC,
		// STREAM, nOFB and OFB modes. It needs to be random and unique (but not secret).
		// The same IV must be used for encryption/decryption.
		// If you do not want to use it you should set it to zeros, but this is not recommended.
		@mcrypt_generic_init ( $td, $key, '' );
		// $iv 在ecb模式中被忽略,其它模式必须补充该值
		// @mcrypt_generic_init ( $td, $key, $iv );
		// 初始处理
		$decrypted = mdecrypt_generic ( $td, $encrypted );
		// 解密
		mcrypt_generic_deinit ( $td );
		// 结束
		mcrypt_module_close ( $td );
		$y = $this->pkcs5_unpad ( $decrypted );
		return $y;
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
		$encrypted = openssl_encrypt ( $str, 'DES-ECB', $this->key, false, $this->iv );
		return bin2hex ( base64_decode ( $encrypted ) );
	}
	/**
	 * openssl 兼容处理方式,如果出现兼容问题.直接切换函数测试或覆盖代码.
	 */
	function ops_decrypt($cipher) {
		$cipher = hex2bin ( $cipher );
		$iv = $this->iv;
		$decrypted = openssl_decrypt ( $cipher, 'DES-ECB', $this->key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $this->iv );
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
