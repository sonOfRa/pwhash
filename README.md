# pwhash

Pwhash is a library inspired by ``password_hash()`` family of function in the PHP standard library. It is meant to offer
modern password hashing algorithms to be used by a unified interface allowing simple hashing, verification and upgrading
of existing hashes

## Supported algorithms

For now, it is planned to support bcrypt and argon2i as modern password hashing algorithms. The interface can be extended
to easily include newer strategies if they become available.

### Argon2

For argon2, this library uses [this library](https://github.com/phxql/argon2-jvm). It comes in two flavors, one with the
native libraries bundled, and one without the native libraries bundled. This is why the dependency to it is listed as
provided in the [pom](pom.xml). This means that when depending on this library, you also need to depend on either
```xml
<dependency>
    <groupId>de.mkammerer</groupId>
    <artifactId>argon2-jvm</artifactId>
    <version>2.3</version>
</dependency>
```
or
```xml
<dependency>
    <groupId>de.mkammerer</groupId>
    <artifactId>argon2-jvm-nolibs</artifactId>
    <version>2.3</version>
</dependency>
```
If you depend on the former, you will need to install the argon2 native libraries on your system. If you depend on the latter,
they will come bundled with the JVM library.
