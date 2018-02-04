[![Build Status](https://travis-ci.org/sonOfRa/pwhash.svg?branch=master)](https://travis-ci.org/sonOfRa/pwhash)
[![Quality Gate](https://sonarcloud.io/api/badges/gate?key=de.slevermann:pwhash)](https://sonarcloud.io/dashboard/index/de.slevermann:pwhash)
[![SonarCloud Coverage](https://sonarcloud.io/api/badges/measure?key=de.slevermann:pwhash&metric=coverage)](https://sonarcloud.io/component_measures/metric/coverage/list?id=de.slevermann:pwhash)
[![SonarCloud Bugs](https://sonarcloud.io/api/badges/measure?key=de.slevermann:pwhash&metric=bugs)](https://sonarcloud.io/component_measures/metric/reliability_rating/list?id=de.slevermann:pwhash)
[![SonarCloud Vulnerabilities](https://sonarcloud.io/api/badges/measure?key=de.slevermann:pwhash&metric=vulnerabilities)](https://sonarcloud.io/component_measures/metric/security_rating/list?id=de.slevermann:pwhash)

# pwhash

Pwhash is a library inspired by ``password_hash()`` family of function in the PHP standard library. It is meant to offer
modern password hashing algorithms to be used by a unified interface allowing simple hashing, verification and upgrading
of existing hashes

## Supported algorithms

For now, it is planned to support argon2 and bcrypt as modern password hashing algorithms. The interface can be extended
to easily include newer strategies if they become available.

### Modern
#### Argon2

For argon2, this library uses [this library](https://github.com/phxql/argon2-jvm). It comes in two flavors, one with the
native libraries bundled, and one without the native libraries bundled. This is why the dependency to it is listed as
provided in the [pom](pom.xml). This means that when depending on this library, you also need to depend on either
```xml
<dependency>
    <groupId>de.mkammerer</groupId>
    <artifactId>argon2-jvm-nolibs</artifactId>
</dependency>
```
or
```xml
<dependency>
    <groupId>de.mkammerer</groupId>
    <artifactId>argon2-jvm</artifactId>
</dependency>
```
If you depend on the former, you will need to install the argon2 native libraries on your system. If you depend on the latter,
they will come bundled with the JVM library.

#### Bcrypt

Bcrypt is supported via [jBcrypt](https://github.com/jeremyh/jBCrypt)

### Compatibility
#### PBKDF2
PBKDF2 is supported for use with older, existing password hashes. It should not be used for new applications.
Currently, the library supports the flavors using SHA512, SHA256 and SHA1.

## Maven dependency
### Release version
The root ``pom.xml`` of this project functions as a [BOM](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html).
In order to use it, add this to your ``<dependencyManagement>`` section in your ``pom.xml``
```xml
<dependencyManagement>
    <dependency>
        <groupId>de.slevermann</groupId>
        <artifactId>pwhash</artifactId>
        <version>3.0.0</version>
        <scope>import</scope>
        <type>pom</type>
    </dependency>
</dependencyManagement>
```

After this, you can define your dependencies without specifying versions, as they are handled by the BOM.
For core support, you need to depend on
```xml
<dependency>
    <groupId>de.slevermann</groupId>
    <artifactId>pwhash-core</artifactId>
</dependency>
```
and your choice of one argon2 provider as listed above.

#### PBKDF2 support
If you also need PBKDF2 support for legacy reasons, use

```xml
<dependency>
    <groupId>de.slevermann</groupId>
    <artifactId>pwhash-pbkdf2</artifactId>
</dependency>
```

#### Unix crypt support
In case you need to support old crypt-style password hashes, use
```xml
<dependency>
    <groupId>de.slevermann</groupId>
    <artifactId>pwhash-crypt</artifactId>
</dependency>
```

### Development version
For the current development snapshot version, use
```xml
<dependency>
    <groupId>de.slevermann</groupId>
    <artifactId>pwhash</artifactId>
    <version>3.1.0-SNAPSHOT</version>
    <scope>import</scope>
    <type>pom</type>
</dependency>
``` 