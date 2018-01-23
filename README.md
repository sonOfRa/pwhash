# pwhash

Pwhash is a library inspired by ``password_hash()`` family of function in the PHP standard library. It is meant to offer
modern password hashing algorithms to be used by a unified interface allowing simple hashing, verification and upgrading
of existing hashes

## Supported algorithms

For now, it is planned to support bcrypt and argon2i as modern password hashing algorithms. The interface can be extended
to easily include newer strategies if they become available.