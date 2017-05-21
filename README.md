MyBlowfish
==========

MyBlowfish is a simple PHP class for passwords hashing and checking using Blowfish algorithm.

It was originally developed for [ATK14 Framework](http://www.atk14.net/). But it can be fit in any other application.

Basic usage
-----------

    $password = "honeyBump";
    MyBlowfish::IsHash($password); // false

    $hash = MyBlowfish::GetHash($password);
    MyBlowfish::IsHash($hash); // true
    
    MyBlowfish::CheckPassword("honeyBumb",$hash); // true
    MyBlowfish::CheckPassword("badTry",$hash); // false

    $hash2 = MyBlowfish::GetHash($password); // $hash2 != $hash

    MyBlowfish::CheckPassword("honeyBumb",$hash2); // true


Popular integration into a ATK14 project
----------------------------------------

Consider a table 'users' which has among the others textual fields 'login' and 'password'.
In the field 'password' we don't want to store passwords in the readable form. We just want to store Blowfish hashes in there.
This can be achieved in the model class User.

    <?php
    // file: app/models/user.php
    class User extends ApplicationModel {

      /**
       * Upon a new user creation it provides transparent password hashing when it's needed
       *
       *    $user = User::CreateNewRecord(array(
       *      "login" => "rambo",
       *      "password" => "secret123"
       *    ));
       */
      static function CreateNewRecord($values,$options = array()){
        if(!MyBlowfish::IsHash($values["password"])){
          $values["password"] = MyBlowfish::GetHash($values["password"]);
        }
        return parent::CreateNewRecord($values,$options);
      }

      /**
       * It provides transparent password hashing during setting new values
       *
       *    $rambo->setValues(array("password" => "newModelArmy"));
       */
      function setValues($values,$options = array()){
        if(isset($values["password"]) && !MyBlowfish::IsHash($values["password"])){
          $values["password"] = MyBlowfish::GetHash($values["password"]);
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
        if(MyBlowfish::CheckPassword($password,$this->getPassword())){
          return $user;
        }
      }
    }

Let's test it in the ATK14 console:

    php > $user = User::CreateNewRecord(array('login' => 'rambo', 'password' => 'secret123'));
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

    composer require yarri/my-blowfish dev-master

License
-------

MyBlowfish is free software distributed [under the terms of the MIT license](http://www.opensource.org/licenses/mit-license)

[//]: # ( vim: set ts=2 et: )
