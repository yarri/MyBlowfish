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

		$exception_thrown = false;
		try {
			MyBlowfish::CheckPassword("BadTry","Not hash!");
		} catch(Exception $e) {
			//
			$exception_thrown = true;
			$this->assertEquals("MyBlowfish: CheckPassword() expects a hash in the second parameter",$e->getMessage());
		}
		$this->assertTrue($exception_thrown);
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

	function test_Hash(){
		$hash = MyBlowfish::Hash('daisy');
		$hash2 = MyBlowfish::Hash('daisy');

		$this->assertTrue(MyBlowfish::IsHash($hash));
		$this->assertTrue(MyBlowfish::IsHash($hash2));

		$this->assertNotEquals($hash,$hash2);

		$this->assertEquals('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm',MyBlowfish::Hash('$2a$06$tZ5j22vjVOFzYy0oVyUH8O3/wFl9M7HJ8tRopF5HaRMdPStdj3Itm'));
		$this->assertEquals('',MyBlowfish::Hash(''));
		$this->assertEquals(null,MyBlowfish::Hash(null));
	}
}
