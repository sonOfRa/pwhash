/**
 * Classes for password hashing with Argon2
 * <p>
 * Argon2, which won the Password Hashing Competition in 2015, should generally be your first choice when implementing
 * password hashing in a new application. Unless you have special requirements and you know exactly what the different
 * versions like argon2i, argon2id, and argon2d do, you should pick the default implementation, which is argon2id.
 *
 * @author Simon Levermann
 * @since 1.0.0
 */
package de.slevermann.pwhash.argon2;