MyBlowfish
==========

[![Tests](https://github.com/yarri/MyBlowfish/actions/workflows/tests.yml/badge.svg)](https://github.com/yarri/MyBlowfish/actions/workflows/tests.yml)
[![Downloads](https://img.shields.io/packagist/dt/yarri/my-blowfish.svg)](https://packagist.org/packages/yarri/my-blowfish)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/67fd234a1b1240dcaf340eb8938e5758)](https://www.codacy.com/gh/yarri/MyBlowfish/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=yarri/MyBlowfish&amp;utm_campaign=Badge_Grade)

MyBlowfish is a simple PHP class for password hashing and checking using the Blowfish (bcrypt) algorithm.

It was originally developed for [ATK14 Framework](http://www.atk14.net/), but it can be used in any application.

- [Installation](#installation)
- [Basic usage](#basic-usage)
- [Blowfish rounds](#blowfish-rounds)
- [Blowfish hash prefixes](#blowfish-hash-prefixes)
- [A popular integration into an ATK14 project](#a-popular-integration-into-an-atk14-project)
- [Testing](#testing)
- [License](#license)

Installation
------------

```bash
composer require yarri/my-blowfish
```

Basic usage
-----------

```php
$password = "honeyBump";
MyBlowfish::IsHash($password); // false

$hash = MyBlowfish::Filter($password);
MyBlowfish::IsHash($hash); // true

// A different salt is used automatically in another call of Filter().
// So the new hash from the same password differs from the old one.
$hash2 = MyBlowfish::Filter($password); // $hash2 !== $hash

// Filter() doesn't make hash from a hash!
$hash3 = MyBlowfish::Filter($hash); // $hash3 === $hash

// There is also method GetHash() which makes hash in every case.
$hash4 = MyBlowfish::GetHash($hash); // $hash4 !== $hash

MyBlowfish::CheckPassword($password, $hash);     // true
MyBlowfish::CheckPassword("badTry", $hash);      // false
MyBlowfish::CheckPassword($hash, $hash);         // false

MyBlowfish::CheckPassword($password, $hash2);    // true

MyBlowfish::CheckPassword($password, $hash4);    // false
MyBlowfish::CheckPassword($hash, $hash4);        // true

MyBlowfish::CheckPassword($password, $password); // false; 2nd param is not a blowfish hash
```

Blowfish rounds
---------------

The complexity of a Blowfish hash calculation can be affected by the number of rounds. The higher the value, the more time-consuming the password cracking process becomes. The default value in MyBlowfish is 12.

The number of rounds can be set by the constant `MY_BLOWFISH_ROUNDS`:

```php
// min     .. 4
// max     .. 31
// optimal .. 10, 11, 12
// default .. 12
define('MY_BLOWFISH_ROUNDS', 12);
```

Beware that high values of Blowfish rounds may lead to unacceptably long hash calculation times.

Blowfish hash prefixes
----------------------

Blowfish hashes are prefixed with either `$2a$`, `$2b$` or `$2y$`. MyBlowfish can handle all of them.

The default prefix is `$2y$`, which is the recommended modern variant — it fixes a bug present in the original `$2a$` implementation.

The default prefix can be changed via the constant `MY_BLOWFISH_PREFIX`:

```php
// default .. '$2y$'
define('MY_BLOWFISH_PREFIX', '$2b$');
```

A popular integration into an ATK14 project
-------------------------------------------

Consider a table `users` which has among other fields `login` and `password`.
Passwords should never be stored in plain text — only as Blowfish hashes.
This can be achieved transparently in the model class `User`:

```php
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
  static function CreateNewRecord($values, $options = []) {
    if (isset($values["password"])) {
      $values["password"] = MyBlowfish::Filter($values["password"]);
    }
    return parent::CreateNewRecord($values, $options);
  }

  /**
   * It provides transparent password hashing during setting new values
   *
   *    $rambo->setValues(["password" => "newModelArmy"]);
   */
  function setValues($values, $options = []) {
    if (isset($values["password"])) {
      $values["password"] = MyBlowfish::Filter($values["password"]);
    }
    return parent::setValues($values, $options);
  }

  /**
   * Returns user when login and password are correct and user is active and not deleted
   * 
   *    $user = User::Login("rambo","secret123");
   */
  static function Login($login,$password,&$bad_password = false){
    $bad_password = false;
    $user = User::FindByLogin($login);
    if(!$user){ return; }
    if($user->isDeleted()){ return; }
    if(!$user->isActive()){ return; }
    if($user->isPasswordCorrect($password)){
      return $user;
    }
    $bad_password = true;
  }

  function isPasswordCorrect($password){
    return MyBlowfish::CheckPassword($password,$this->getPassword());
  }
}
```

Let's test it in the ATK14 console:

```
php > $user = User::CreateNewRecord(['login' => 'rambo', 'password' => 'secret123']);
php > echo $user->getPassword();
$2y$12$w984Nf6g67ZZKqvXgQWqwuj4mOn9Ptmw.dMNs/A7G9Cj/mt/w5buy
php > $user->setValue('password', 'newModelArmy');
php > echo $user->getPassword();
$2y$12$2ljCknUGAtf5lSAo0txoFO9qqGH2dxLDr31Ii4VSHca0Zb8cHZZgu
php > $user->setValue('password', '$2y$12$2ljCknUGAtf5lSAo0txoFO9qqGH2dxLDr31Ii4VSHca0Zb8cHZZgu');
php > echo $user->getPassword();
$2y$12$2ljCknUGAtf5lSAo0txoFO9qqGH2dxLDr31Ii4VSHca0Zb8cHZZgu
```

Testing
-------

MyBlowfish is tested automatically via GitHub Actions across PHP 5.6 to PHP 8.5.

Tests use the [atk14/tester](https://packagist.org/packages/atk14/tester) wrapper for [phpunit/phpunit](https://packagist.org/packages/phpunit/phpunit).

Install development dependencies:

```bash
composer update --dev
```

Run the test suite:

```bash
cd test
../vendor/bin/run_unit_tests
```

License
-------

MyBlowfish is free software distributed [under the terms of the MIT license](http://www.opensource.org/licenses/mit-license)

[//]: # ( vim: set ts=2 et: )
