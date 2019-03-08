# Change Log
All notable changes to this project will be documented in this file.

## [Unreleased]

### Removed
- When the second parameter in MyBlowfish::CheckPassword() is not a hash, exception is not thrown - throwing exceptions seemed to be an antipattern

## [1.2] 2018-10-23

- Added support for $2b$ and $2y$ hash prefixes
- Dropped out dependency on atk14/string4 package
- MyBlowfish::RandomString() fixed & tuned & tested

## [1.1.1] 2018-07-04

### Added
- Exception is thrown when the second parameter of MyBlowfish::CheckPassword() is not a hash

## [1.1] 2018-04-11

### Added
- Added method MyBlowfish::Hash() for easier integration into projects

## [1.0] 2017-08-30

First official release
