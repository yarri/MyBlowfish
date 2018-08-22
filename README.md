MyBlowfish
==========

MyBlowfish is a simple PHP class for passwords hashing and checking using Blowfish algorithm.

It was originally developed for [ATK14 Framework](http://www.atk14.net/). But it can be fit in any other application.

Basic usage
-----------

    $password = "honeyBump";
    MyBlowfish::IsHash($password); // false

    $hash = MyBlowfish::Hash($password);
    MyBlowfish::IsHash($hash); // true

    // A different salt is used automatically in another call of Hash().
    // So the new hash from the same password differs from the old one.
    $hash2 = MyBlowfish::Hash($password); // $hash2 !== $hash

    // Hash() doesn't make hash from a hash!
    $hash3 = MyBlowfish::Hash($hash); // $hash3 === $hash
    
    // There is also method GetHash() which makes hash in every case.
    $hash4 = MyBlowfish::GetHash($hash); // $hash4 !== $hash

    MyBlowfish::CheckPassword($password,$hash); // true
    MyBlowfish::CheckPassword("badTry",$hash); // false
    MyBlowfish::CheckPassword($hash,$hash); // false

    MyBlowfish::CheckPassword($password,$hash2); // true

    MyBlowfish::CheckPassword($password,$hash4); // false
    MyBlowfish::CheckPassword($hash,$hash4); // true

    // An exception is thrown when the second parameter in CheckPassword() is not a hash.
    MyBlowfish::CheckPassword($password,$password); // throws an exception

Blowfish rounds
---------------

Complexity of calculation of a Blowfish hash can be affected by the number of Blowfish rounds. The higher value of Blowfish rounds is, the more time consumption the password cracking process can be. In MyBlowfish the default value is set to 12.

Number of Blowfish rounds can be set by the constant MY_BLOWFISH_ROUNDS.

    // min .. 4
    // max .. 31
    // optimal .. 10, 11, 12
    // default .. 12
    define("MY_BLOWFISH_ROUNDS",12);

Beware that high values of Blowfish rounds may lead to unwanted long time of hash calculation.

Popular integration into a ATK14 project
----------------------------------------

Consider a table 'users' which has among the others textual fields 'login' and 'password'.
In the field 'password' we don't want to store passwords in the readable form. We just want to store Blowfish hashes in there.
This can be achieved in the model class User.

    <?php
    // file: app/models/user.php
    class User extends ApplicationModel {

      /**
       * During a new user creation it provides transparent password hashing when it's needed
       *
       *    $user = User::CreateNewRecord([
       *      "login" => "rambo",
       *      "password" => "secret123"
       *    ]);
       */
      static function CreateNewRecord($values,$options = []){
        if(isset($values["password"])){
          $values["password"] = MyBlowfish::Hash($values["password"]);
        }
        return parent::CreateNewRecord($values,$options);
      }

      /**
       * It provides transparent password hashing during setting new values
       *
       *    $rambo->setValues(["password" => "newModelArmy"]);
       */
      function setValues($values,$options = []){
        if(isset($values["password"])){
          $values["password"] = MyBlowfish::Hash($values["password"]);
        }
        return parent::setValues($values,$options);
      }
      
      /**
       * Returns user when a correct combination of login and password is given.
       *
       *    $user = User::Login("rambo","secret123");
       */
      static function Login($login,$password){
        $user = User::FindByLogin($login);
        if(!$user){ return; }
        if(MyBlowfish::CheckPassword($password,$user->getPassword())){
          return $user;
        }
      }
    }

Let's test it in the ATK14 console:

    php > $user = User::CreateNewRecord(['login' => 'rambo', 'password' => 'secret123']);
    php > echo $user->getPassword();
    $2a$12$w984Nf6g67ZZKqvXgQWqwuj4mOn9Ptmw.dMNs/A7G9Cj/mt/w5buy
    php > $user->setValue('password','newModelArmy');
    php > echo $user->getPassword();
    $2a$12$2ljCknUGAtf5lSAo0txoFO9qqGH2dxLDr31Ii4VSHca0Zb8cHZZgu
    php > $user->setValue('password','$2a$12$2ljCknUGAtf5lSAo0txoFO9qqGH2dxLDr31Ii4VSHca0Zb8cHZZgu');
    php > echo $user->getPassword();
    $2a$12$2ljCknUGAtf5lSAo0txoFO9qqGH2dxLDr31Ii4VSHca0Zb8cHZZgu

Installation
------------

The best way how to install LinkFinder is to use the Composer:

    composer require yarri/my-blowfish

License
-------

MyBlowfish is free software distributed [under the terms of the MIT license](http://www.opensource.org/licenses/mit-license)

[//]: # ( vim: set ts=2 et: )
