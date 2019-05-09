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
		$this->assertFalse(MyBlowfish::IsHash("secret"));
		$this->assertTrue(MyBlowfish::IsHash('$2a$12$MynqSpHoDzQmzFHA5ZcDsesX1pBw9RQzqtJEFqpeZhpawmnC4MUK.'));
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
		$this->assertEquals('$2a$06$stW/wJf6Vi/tpZSU8hfaUunZSV6HfRQQZ1Q6nPKYNuiMnxaJW80OW',$hash);

		$hash = MyBlowfish::GetHash("daisy",'$2a$04$stW/wJf6Vi/tpZSU8hfaUu');
		$this->assertEquals('$2a$04$stW/wJf6Vi/tpZSU8hfaUuJWCk5FfPzTmpkuD7ibhbvAzq5rfvP96',$hash);

		$hash = MyBlowfish::GetHash("daisy","custom.salt");
		$this->assertEquals('$2a$06$custom.saltcustom.saleucWYyQaxH2rDiWWhdmb283OjmmpMx/O',$hash);

		$exception_thrown = false;
		try {
			$hash = MyBlowfish::GetHash("daisy","custom.salt!!!"); // invalid characters in hash
		} catch(Exception $e) {
			//
			$exception_thrown = true;
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

	function test_prefixes(){
		$this->_test_prefix('$2a$');
		if(!preg_match('/^5\.3\./',phpversion())){
			$this->_test_prefix('$2b$'); // In PHP5.3 there is no support for $2b$ blowfish prefix
		}
		$this->_test_prefix('$2y$');
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
