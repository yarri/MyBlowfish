<?php
if(!defined("MY_BLOWFISH_ESCAPE_NON_ASCII_CHARS")){
	// There are some issues with hashing non-ascii passwords
	// http://www.php.net/security/crypt_blowfish.php
	define("MY_BLOWFISH_ESCAPE_NON_ASCII_CHARS",true);
}

if(!defined("MY_BLOWFISH_ROUNDS")){
	// The higher this constant is the more time consumption a hash calculation is
	// min .. 4
	// max .. 31
	// optimal .. 12
	define("MY_BLOWFISH_ROUNDS",12);
}

/**
 * Provides methods for hashing passwords and comparing hashed passwords.
 * It uses blowfish hash algorithm.
 *  
 * <code>
 *   $hash = MyBlowfish::GetHash("secret");
 *   if(MyBlowfish::CheckPassword("secret",$hash)){
 *     // good password
 *   }
 * </code>
 *
 * Inspiration:
 *  http://stackoverflow.com/questions/4795385/how-do-you-use-bcrypt-for-hashing-passwords-in-php
 *
 * TODO:
 *  Consider $2x$ and $2y$ hashes
 */
class MyBlowfish{

	/**
	 * Hashes the given password. Doesn't do anything if an already hashed password is given.
	 *
	 * Returns null or empty string if null or empty string is given.
	 *
	 * <code>
	 *    echo MyBlowfish::Hash("daisy"); // $2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm
	 *    echo MyBlowfish::Hash("daisy"); // $2a$06$oU6VBb0Y7/h648HIgDiosukfS0y97pRJOrndqHPunsEZ/2Ykez3Rm
	 *	
	 *		echo MyBlowfish::Hash('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm'); // $2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm
	 *
	 * 		echo MyBlowfish::Hash(""); // ""
	 * 		echo MyBlowfish::Hash(null); // null
	 * </code>
	 *
	 */
	static function Hash($password){
		if(strlen($password)==0){
			return $password;
		}

		if(self::IsHash($password)){
			return $password;
		}

		return self::GetHash($password);
	}

	/**
	 * Hashes the given password
	 *
	 * <code>
	 *  $hash = MyBlowfish::GetHash("secret");
	 *  $hash = MyBlowfish::GetHash("secret","SomeSalt");
	 *  $hash = MyBlowfish::GetHash("secret","$2a$08$GEw8HjtpaK0WfdILVMby7u");
	 * </code>
	 *
	 * An exception is thrown when something went wrong.
	 * 
	 * @static
	 * @access public
	 * @param string $password                readable password
	 * @param string $salt                    optional salt
	 *                                        - salt must start with phrase "$2a$DD$" where DD are decimal nubers
	 *                                        - salt must be 29 chars long
	 *                                        - MyBlowfish tries to correct the given salt when the needs are not met, an exception can be thrown when the the final salt is not correct
	 *                                        - it's recommended to omit the salt, it will be determined automatically :)
	 * @return string                         hash
	 */
	static function GetHash($password,$salt = "",$options = array()){
		if(is_array($salt)){
			$options = $salt;
			$salt = "";
		}

		if(!defined("CRYPT_BLOWFISH") || CRYPT_BLOWFISH!=1) {
      throw new Exception("MyBlowfish: Blowfish not supported in this installation. See http://php.net/crypt");
    }

		$options += array(
			"salt" => $salt,
			"escape_non_ascii_chars" => MY_BLOWFISH_ESCAPE_NON_ASCII_CHARS,
			"rounds" => MY_BLOWFISH_ROUNDS,
		);

		$password = (string)$password;
		$salt = (string)$options["salt"];

		if($options["escape_non_ascii_chars"]){
			$password = static::EscapeNonAsciiChars($password);
		}

		// The higher ROUNDS is, the more expensive hash calculation is
		$__salt = sprintf('$2a$%02d$',$options["rounds"]);

		if(strlen($salt)==0){
			$__salt .= static::RandomString(22);
		}else{
			$salt_prefix = $__salt;
			$salt_random = "";
			if(preg_match('/^(\$..\$[0-9]+\$)(.*)/',$salt,$matches)){
				$salt_prefix = $matches[1];
				$salt_random = $matches[2];
			}else{
				$salt_random = $salt;
			}

			if($salt_random==""){ $salt_random = static::RandomString(22); }

			while(strlen($salt_random)<22){
				$salt_random .= $salt_random;
			}
			$salt_random = substr($salt_random,0,22);

			$salt = "$salt_prefix$salt_random";

			if(strlen($salt)!=29){
				throw new Exception(sprintf("MyBlowfish: salt must be 29 chars long (it is %s)",strlen($salt)));
			}
			if(!preg_match('/^\$2a\$[0-9]{2}\$/',$salt)){
				throw new Exception(sprintf('MyBlowfish: salt must start with phrase $2a$DD$ where DD are defined numbers'));
			}
			$__salt = $salt;
		}

		$__hash = crypt($password,$__salt);
		if(!self::IsHash($__hash)){
			throw new Exception("MyBlowfish: hashing failed");
		}
		return $__hash;
	}

	/**
	 * Checks whether the given readable password matches the given hash
	 *
	 *  if(MyBlowfish::CheckPassword('kolovrat','$2a$08$GEw8HjtpaK0WfdILVMby7uvjpWSvu0aF/U6Qx6r.xg.qdDSFg9zBm')){
	 *    // correct password given
	 *  }
	 *
	 * @static
	 * @access public
	 * @param string $password      readable password
	 * @param string $hash          expected hash of the password
	 * @return boolean              true -> correct password
	 *                              false -> invalid password
	 */
	static function CheckPassword($password,$hash,$options = array()){
		$password = (string)$password;
		$hash = (string)$hash;

		$options += array(
			"escape_non_ascii_chars" => MY_BLOWFISH_ESCAPE_NON_ASCII_CHARS,
		);

		if(!static::IsHash($hash)){
			throw new Exception("MyBlowfish: CheckPassword() expects a hash in the second parameter");
		}

		$exp_h1 = static::GetHash($password,$hash,$options);

		if(static::_CompareHashes($exp_h1,$hash)){ return true; }

		// let's try to toggle the non-ascii chars conversion and compare password again
		$options["escape_non_ascii_chars"] = !$options["escape_non_ascii_chars"];
		$exp_h2 = static::GetHash($password,$hash,$options);

		return static::_CompareHashes($exp_h2,$hash);
	}

	/**
	 * Is the given string a valid BLOWFISH hash?
	 */
	static function IsHash($value){
		return strlen($value)==60 && preg_match('/^\$2a\$[0-9]{2}\$/',$value);
	}

	static function RandomString($length = 22){
		$bytes = null;

    if(function_exists('openssl_random_pseudo_bytes')){
      $bytes = openssl_random_pseudo_bytes($length);

    }elseif(function_exists('mcrypt_create_iv')){
			$bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);

		}

		if(isset($bytes)){
			$out = static::_EncodeBytes($bytes);
			if(strlen($out)==$length){
				return $out;
			}
		}

		// Beware, String4 provides weak randomness
		return (string)String4::RandomString($length);
	}

  private static function _EncodeBytes($input) {
    // The following code is from the PHP Password Hashing Framework
    $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    $output = '';
    $index = 0;
    do {
      $char1 = ord($input[$index++]);
      $output .= $itoa64[$char1 >> 2];
      $char1 = ($char1 & 0x03) << 4;
      if ($index >= 16) {
        $output .= $itoa64[$char1];
        break;
      }

      $char2 = ord($input[$index++]);
      $char1 |= $char2 >> 4;
      $output .= $itoa64[$char1];
      $char1 = ($char2 & 0x0f) << 2;

      $char2 = ord($input[$index++]);
      $char1 |= $char2 >> 6;
      $output .= $itoa64[$char1];
      $output .= $itoa64[$char2 & 0x3f];
    } while (1);

    return $output;
  }

	/**
	 * Provides safely encoding non-ascii characters into series of ascii chars
	 *
	 *  $encoded = MyBlowfish::EscapeNonAsciiChars("hřebíček"); // h\xc5\x99eb\xc3\xad\xc4\x8dek
	 */
	static function EscapeNonAsciiChars($password){
		$chrs = array();
		for($i=0;$i<strlen($password);$i++){
			$chr = $password[$i];
			if(ord($chr)>127 || $chr=="\\"){
				$chrs[] = '\x'.strtolower(dechex(ord($chr)));
				continue;
			}
			$chrs[] = $chr;
		}
		return join("",$chrs);
	}


	private static function _CompareHashes($hash1,$hash2){
		if(
			!static::IsHash($hash1) ||
			!static::IsHash($hash2)
		){ return false; }

		return strcmp($hash1,$hash2)===0;
	}
}
