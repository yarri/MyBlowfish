<?php
class TcMyBlowfish extends TcBase {

	function test(){
		$pasword = "BigJohnRulez";

		$hash = MyBlowfish::GetHash($pasword);
		$hash2 = MyBlowfish::GetHash($pasword);

		$this->assertEquals(60,strlen($hash));
		$this->assertEquals(60,strlen($hash2));

		$this->assertTrue($hash!=$hash2);

		$this->assertFalse(MyBlowfish::IsHash($pasword));
		$this->assertTrue(MyBlowfish::IsHash($hash));
		$this->assertTrue(MyBlowfish::IsHash($hash2));

		$this->assertTrue(MyBlowfish::CheckPassword($pasword,$hash));
		$this->assertTrue(MyBlowfish::CheckPassword($pasword,$hash2));

		$this->assertFalse(MyBlowfish::CheckPassword("BadTry",$hash));
		$this->assertFalse(MyBlowfish::CheckPassword("BadTry",$hash2));

		$this->assertFalse(MyBlowfish::CheckPassword($hash,$hash));

		$hashed_hash = MyBlowfish::GetHash($hash);
		$this->assertNotEquals($hash,$hashed_hash);
		$this->assertTrue(MyBlowfish::IsHash($hashed_hash));
		//
		$this->assertTrue(MyBlowfish::CheckPassword($hash,$hashed_hash));
		$this->assertFalse(MyBlowfish::CheckPassword($hashed_hash,$hash));
		
		$this->assertFalse(MyBlowfish::CheckPassword("BadTry","BadTry"));
		$this->assertFalse(MyBlowfish::CheckPassword("",""));
		$this->assertFalse(MyBlowfish::CheckPassword(null,null));
		$this->assertFalse(MyBlowfish::CheckPassword("BadTry","Not hash!"));

		/*
		$exception_thrown = false;
		try {
			MyBlowfish::CheckPassword("BadTry","Not hash!");
		} catch(Exception $e) {
			//
			$exception_thrown = true;
			$this->assertEquals("MyBlowfish: CheckPassword() expects a hash in the second parameter",$e->getMessage());
		}
		$this->assertTrue($exception_thrown);
		*/
	}

	function test_IsHash(){
		$valid_hash = '$2y$12$MynqSpHoDzQmzFHA5ZcDsesX1pBw9RQzqtJEFqpeZhpawmnC4MUK.';

		$this->assertFalse(MyBlowfish::IsHash("secret"));
		$this->assertTrue(MyBlowfish::IsHash($valid_hash));

		$this->assertFalse(MyBlowfish::IsHash(substr($valid_hash,0,59))); // too short (59 chars)
		$this->assertFalse(MyBlowfish::IsHash($valid_hash.".")); // too long (61 chars)

		$this->assertFalse(MyBlowfish::IsHash('$2x$'.substr($valid_hash,4))); // invalid variant letter
	}

	function test_EscapeNonAsciiChars(){
		$this->assertEquals("OpenSezame123$%@/*",MyBlowfish::EscapeNonAsciiChars("OpenSezame123$%@/*"));
		$this->assertEquals('h\xc5\x99eb\xc3\xad\xc4\x8dek',MyBlowfish::EscapeNonAsciiChars("hřebíček"));
		$this->assertEquals('Black\x5cWhite',MyBlowfish::EscapeNonAsciiChars("Black\White"));
	}

	function test_salting(){
		$hash = MyBlowfish::GetHash("daisy",'$2a$06$stW/wJf6Vi/tpZSU8hfaUu');
		$this->assertEquals('$2a$06$stW/wJf6Vi/tpZSU8hfaUunZSV6HfRQQZ1Q6nPKYNuiMnxaJW80OW',$hash);

		$hash = MyBlowfish::GetHash("daisy",'stW/wJf6Vi/tpZSU8hfaUu');
		$this->assertEquals('$2y$06$stW/wJf6Vi/tpZSU8hfaUunZSV6HfRQQZ1Q6nPKYNuiMnxaJW80OW',$hash);

		$hash = MyBlowfish::GetHash("daisy",'$2a$04$stW/wJf6Vi/tpZSU8hfaUu');
		$this->assertEquals('$2a$04$stW/wJf6Vi/tpZSU8hfaUuJWCk5FfPzTmpkuD7ibhbvAzq5rfvP96',$hash);

		$hash = MyBlowfish::GetHash("daisy","custom.salt");
		$this->assertEquals('$2y$06$custom.saltcustom.saleucWYyQaxH2rDiWWhdmb283OjmmpMx/O',$hash);

		$exception_thrown = false;
		try {
			$hash = MyBlowfish::GetHash("daisy","custom.salt!!!"); // invalid characters in hash
		} catch(Exception $e) {
			//
			$exception_thrown = true;
		}
		$this->assertTrue($exception_thrown);
	}

	function test_NonAsciiPassword(){
		$password = "hřebíček";
		$salt = '$2y$06$stW/wJf6Vi/tpZSU8hfaUu';

		// same password+salt but escaping on/off must produce different hashes
		$hash_escaped = MyBlowfish::GetHash($password,$salt,array("escape_non_ascii_chars" => true));
		$hash_not_escaped = MyBlowfish::GetHash($password,$salt,array("escape_non_ascii_chars" => false));
		$this->assertNotEquals($hash_escaped,$hash_not_escaped);

		// CheckPassword() must recognize both, regardless of which escaping option is passed to it
		// (it transparently toggles and retries when the first attempt doesn't match)
		$this->assertTrue(MyBlowfish::CheckPassword($password,$hash_escaped));
		$this->assertTrue(MyBlowfish::CheckPassword($password,$hash_not_escaped));
		$this->assertTrue(MyBlowfish::CheckPassword($password,$hash_escaped,array("escape_non_ascii_chars" => false)));
		$this->assertTrue(MyBlowfish::CheckPassword($password,$hash_not_escaped,array("escape_non_ascii_chars" => true)));

		$this->assertFalse(MyBlowfish::CheckPassword("hrebicek",$hash_escaped));
		$this->assertFalse(MyBlowfish::CheckPassword("hrebicek",$hash_not_escaped));

		// end to end through the public Filter()/CheckPassword() API
		$hash = MyBlowfish::Filter($password);
		$this->assertTrue(MyBlowfish::IsHash($hash));
		$this->assertTrue(MyBlowfish::CheckPassword($password,$hash));
	}

	function test_salt_with_malformed_rounds_digit_count(){
		// the salt-parsing regex accepts any number of digits for rounds ([0-9]+),
		// so a non-2-digit rounds segment throws when the final salt isn't exactly 29 chars

		$exception_thrown = false;
		try {
			MyBlowfish::GetHash("daisy",'$2a$123$stW/wJf6Vi/tpZSU8hfaUu'); // 3-digit rounds -> 30 chars total
		} catch(Exception $e) {
			$exception_thrown = true;
			$this->assertEquals("MyBlowfish: salt must be 29 chars long (it is 30)",$e->getMessage());
		}
		$this->assertTrue($exception_thrown);

		$exception_thrown = false;
		try {
			MyBlowfish::GetHash("daisy",'$2a$6$stW/wJf6Vi/tpZSU8hfaUu'); // 1-digit rounds -> 28 chars total
		} catch(Exception $e) {
			$exception_thrown = true;
			$this->assertEquals("MyBlowfish: salt must be 29 chars long (it is 28)",$e->getMessage());
		}
		$this->assertTrue($exception_thrown);
	}

	function test_Filter(){
		$hash = MyBlowfish::Filter('daisy');
		$hash2 = MyBlowfish::Filter('daisy');

		$this->assertTrue(MyBlowfish::IsHash($hash));
		$this->assertTrue(MyBlowfish::IsHash($hash2));

		$this->assertNotEquals($hash,$hash2);

		$this->assertEquals('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm',MyBlowfish::Filter('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm'));
		$this->assertEquals('',MyBlowfish::Filter(''));
		$this->assertEquals(null,MyBlowfish::Filter(null));

		// Testing Hash() method which is alias for Filter()
		$hash3 = MyBlowfish::Hash('daisy');
		$this->assertTrue(MyBlowfish::IsHash($hash3));
		$this->assertEquals('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm',MyBlowfish::Hash('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm'));
		$this->assertEquals('',MyBlowfish::Hash(''));
		$this->assertEquals(null,MyBlowfish::Hash(null));
	}

	function test_RandomString(){
		$salt = MyBlowfish::RandomString();
		$salt2 = MyBlowfish::RandomString(22);

		$this->assertTrue(!!preg_match('/^[a-zA-Z0-9\/.]{22}$/',$salt),$salt);
		$this->assertTrue(!!preg_match('/^[a-zA-Z0-9\/.]{22}$/',$salt2),$salt2);

		$this->assertNotEquals($salt,$salt2);

		$salt3 = MyBlowfish::RandomString(30);
		$this->assertTrue(!!preg_match('/^[a-zA-Z0-9\/.]{30}$/',$salt3),$salt3);

		$salt4 = MyBlowfish::RandomString(3333);
		$this->assertTrue(!!preg_match('/^[a-zA-Z0-9\/.]{3333}$/',$salt4),$salt4);
	}

	function test_NeedsRehash(){
		$hash_06 = MyBlowfish::GetHash("daisy",array("rounds" => 6));
		$hash_12 = MyBlowfish::GetHash("daisy",array("rounds" => 12));

		$this->assertTrue(MyBlowfish::NeedsRehash($hash_06,array("rounds" => 12)));
		$this->assertFalse(MyBlowfish::NeedsRehash($hash_12,array("rounds" => 12)));
		$this->assertFalse(MyBlowfish::NeedsRehash($hash_12,array("rounds" => 6))); // more rounds than required -> no need to rehash

		// defaults to MY_BLOWFISH_ROUNDS (set to 6 in test/initialize.php)
		$this->assertFalse(MyBlowfish::NeedsRehash($hash_06));
		$hash_04 = MyBlowfish::GetHash("daisy",array("rounds" => 4));
		$this->assertTrue(MyBlowfish::NeedsRehash($hash_04));

		$this->assertFalse(MyBlowfish::NeedsRehash("not a hash"));
		$this->assertFalse(MyBlowfish::NeedsRehash(""));
		$this->assertFalse(MyBlowfish::NeedsRehash(null));

		// prefix mismatch
		$hash_2a = MyBlowfish::GetHash("daisy",array("rounds" => 6,"prefix" => '$2a$'));
		$hash_2y = MyBlowfish::GetHash("daisy",array("rounds" => 6,"prefix" => '$2y$'));

		$this->assertTrue(MyBlowfish::NeedsRehash($hash_2a,array("rounds" => 6,"prefix" => '$2y$')));
		$this->assertFalse(MyBlowfish::NeedsRehash($hash_2y,array("rounds" => 6,"prefix" => '$2y$')));

		// defaults to MY_BLOWFISH_PREFIX ('$2y$')
		$this->assertTrue(MyBlowfish::NeedsRehash($hash_2a));
		$this->assertFalse(MyBlowfish::NeedsRehash($hash_2y));
	}

	function test_prefixes(){
		$this->_test_prefix('$2a$');
		if(!preg_match('/^5\.3\./',phpversion())){
			$this->_test_prefix('$2b$'); // In PHP5.3 there is no support for $2b$ blowfish prefix
		}
		$this->_test_prefix('$2y$');
	}

	function test_rounds(){
		$hash = MyBlowfish::GetHash("Jupit3R",array("rounds" => 4));
		$this->assertTrue(MyBlowfish::IsHash($hash));

		$exception_thrown = false;
		try {
			$hash = MyBlowfish::GetHash("Jupit3R",array("rounds" => 3));
		} catch(Exception $e) {
			//
			$this->assertEquals("MyBlowfish: rounds out of boundary (rounds must be between 4 and 31 but it is 3)",$e->getMessage());
			$exception_thrown = true;
		}
		$this->assertTrue($exception_thrown);

		$exception_thrown = false;
		try {
			$hash = MyBlowfish::GetHash("Jupit3R",array("rounds" => 32));
		} catch(Exception $e) {
			//
			$this->assertEquals("MyBlowfish: rounds out of boundary (rounds must be between 4 and 31 but it is 32)",$e->getMessage());
			$exception_thrown = true;
		}
		$this->assertTrue($exception_thrown);
	}

	function _test_prefix($prefix){
		$hash = MyBlowfish::GetHash("daisy",$prefix.'06$stW/wJf6Vi/tpZSU8hfaUu');

		$this->assertEquals($prefix.'06$stW/wJf6Vi/tpZSU8hfaUunZSV6HfRQQZ1Q6nPKYNuiMnxaJW80OW',$hash);

		$hash = MyBlowfish::GetHash("daisy",$prefix.'06$');
		$this->assertEquals($prefix.'06$',substr($hash,0,7));

		$this->assertTrue(MyBlowfish::CheckPassword("daisy",$prefix.'06$PaWQ8Ydrq87S8two9Z4LH.0jrJp0aLbo0CRGbVOtGCE3wQVzuV2RG'));

		$this->assertFalse(MyBlowfish::CheckPassword("daisy",$prefix.'06$PaWQ8Ydrq87S8two9Z4LH.0jrJp0aLbo0CRGbVOtGCE3wQVzuV2RX')); // X on the last position

		$hash = MyBlowfish::GetHash("Jupit3R",array("prefix" => $prefix));
		$this->assertEquals($prefix.'06$',substr($hash,0,7));

		$exception_thrown = false;
		try {
			$hash = MyBlowfish::GetHash("Jupit3R",array("prefix" => 'bad_joke'));
		} catch(Exception $e) {
			//
			$this->assertEquals("MyBlowfish: invalid hash prefix: bad_joke",$e->getMessage());
			$exception_thrown = true;
		}
		$this->assertTrue($exception_thrown);
	}
}
