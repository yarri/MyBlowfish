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
	}
}
