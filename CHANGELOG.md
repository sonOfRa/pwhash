# Changelog

## [Unreleased]
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