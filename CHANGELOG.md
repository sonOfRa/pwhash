# Changelog

## [Unreleased]

## [3.0.1] 2019-01-02
### Changed
- Updated dependency versions

## [3.0.0] 2018-02-04
### Removed
- Public custom constructors for BCrypt and Argon2{i,id,d}

### Added
- Maven BOM architecture
- Static ``getInstance`` methods for constructing custom BCrypt and Argon2 instances.
These throw exceptions when invalid values are provided

## [2.1.1] 2018-01-31
### Added
- Example code
- Automatic-Module-Names for JDK 9 module support

## [2.1.0] - 2018-01-30
### Changed
- Maven multi-module architecture

## [2.0.0] - 2018-01-28
### Changed
- verify() can now optionally throw InvalidHashException if the hash given is not verifiable
- All functions expect and output UTF-8 Strings
- The project is now licensed under the Apache License

### Added
- Support for PBKDF2WithHmacSHA{1,256,512}

## [1.0.0] - 2018-01-26
### Added
- Support for bcrypt
- Support for argon2{i,id,d}
- Support for a basic migration strategy
