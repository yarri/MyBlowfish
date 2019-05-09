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

if(!defined("MY_BLOWFISH_PREFIX")){
	// The default Blowfish hash prefix
	// Possible prefixes are:
	// $2a$
	// $2b$
	// $2y$
	define("MY_BLOWFISH_PREFIX",'$2a$');
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
	 *    echo MyBlowfish::Filter("daisy"); // $2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm
	 *    echo MyBlowfish::Filter("daisy"); // $2a$06$oU6VBb0Y7/h648HIgDiosukfS0y97pRJOrndqHPunsEZ/2Ykez3Rm
	 *	
	 *		echo MyBlowfish::Filter('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm'); // $2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm
	 *
	 * 		echo MyBlowfish::Filter(""); // ""
	 * 		echo MyBlowfish::Filter(null); // null
	 * </code>
	 *
	 */
	static function Filter($password){
		if(strlen($password)==0){
			return $password;
		}

		if(self::IsHash($password)){
			return $password;
		}

		return self::GetHash($password);
	}

	/**
	 * Alias for MyBlowfish::Filter()
	 *
	 * Hash method has been renamed to Filter and now Hash is alias for Filter to ensure compatibility with old implementations.
	 */
	static function Hash($password){
		return self::Filter($password);
	}

	/**
	 * Hashes the given password
	 *
	 * <code>
	 *  $hash = MyBlowfish::GetHash("secret");
	 *  $hash = MyBlowfish::GetHash("secret","SomeSalt");
	 *  $hash = MyBlowfish::GetHash("secret","$2a$08$GEw8HjtpaK0WfdILVMby7u");
	 *  $hash = MyBlowfish::GetHash("secret",["prefix" => '$2y$']);
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
			"prefix" => MY_BLOWFISH_PREFIX, // e.g. '$2a$'
			"salt" => $salt,
			"escape_non_ascii_chars" => MY_BLOWFISH_ESCAPE_NON_ASCII_CHARS,
			"rounds" => MY_BLOWFISH_ROUNDS,
		);

		$prefix = $options["prefix"];
		$password = (string)$password;
		$salt = (string)$options["salt"];

		if(!in_array($prefix,array('$2a$','$2b$','$2y$'))){
			throw new Exception(sprintf("MyBlowfish: invalid hash prefix: %s",$prefix));
		}

		if($options["escape_non_ascii_chars"]){
			$password = static::EscapeNonAsciiChars($password);
		}

		// The higher ROUNDS is, the more expensive hash calculation is
		$__salt = sprintf($prefix.'%02d$',$options["rounds"]);

		$salt_prefix = $__salt;
		$salt_random = $salt;
		if(preg_match('/^(\$..\$[0-9]+\$)(.*)/',$salt,$matches)){
			$salt_prefix = $matches[1];
			$salt_random = $matches[2];
		}

		if(strlen($salt_random)==0){ $salt_random = static::RandomString(22); }

		$salt_random = str_repeat($salt_random,ceil(22 / strlen($salt_random)));
		$salt_random = substr($salt_random,0,22);

		$salt = "$salt_prefix$salt_random";

		if(strlen($salt)!=29){
			throw new Exception(sprintf("MyBlowfish: salt must be 29 chars long (it is %s)",strlen($salt)));
		}
		if(!preg_match('/^\$2[aby]\$[0-9]{2}\$/',$salt)){
			throw new Exception(sprintf('MyBlowfish: salt must start with phrase '.$prefix.'DD$ where DD are defined numbers'));
		}
		$__salt = $salt;

		$hash = crypt($password,$__salt);
		if(!self::IsHash($hash)){
			throw new Exception("MyBlowfish: hashing failed");
		}
		return $hash;
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
			return false;
			//throw new Exception("MyBlowfish: CheckPassword() expects a hash in the second parameter");
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
		return strlen($value)==60 && preg_match('/^\$2[aby]\$[0-9]{2}\$/',$value);
	}

	static function RandomString($length = 22){
		$bytes = null;

    if(function_exists('openssl_random_pseudo_bytes')){
      $bytes = openssl_random_pseudo_bytes($length);

    }elseif(function_exists('mcrypt_create_iv')){
			$bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);

		}elseif(function_exists('random_bytes')){
			// random_bytes() exists in PHP7
			$bytes = random_bytes($length);
		}

		if(strlen($bytes)!=$length){
			
			$bytes = "";
			while(strlen($bytes)<$length){
				$bytes .= chr(rand(0,255));
			}
		}

		return static::_EncodeBytes($bytes,$length);
	}

  private static function _EncodeBytes($input,$length) {
    // The following code is from the PHP Password Hashing Framework
    $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    $output = '';
    $index = 0;
    do {
      $char1 = ord($input[$index++]);
      $output .= $itoa64[$char1 >> 2];
      $char1 = ($char1 & 0x03) << 4;
      if (strlen($output) >= $length) {
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

		$output = substr($output,0,$length);

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
