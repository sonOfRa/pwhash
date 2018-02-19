package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Common Superclass for Unix-Crypt based hashing strategies
 *
 * @author Simon Levermann
 */
public abstract class CryptStrategy implements HashStrategy {
    public static final int DEFAULT_SALT_LENGTH = 16;
    public static final String B64_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    protected int saltLength;
    protected final String id;

    private final SecureRandom secureRandom = new SecureRandom();

    protected CryptStrategy(int saltLength, String id) {
        this.saltLength = saltLength;
        this.id = id;
    }

    @Override
    public String hash(String password) {
        return computeHash(password, getSalt());
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {
        String salt = extractSalt(hash);
        if (!salt.startsWith("$" + id)) {
            throw new InvalidHashException("Invalid salt identifier");
        }
        String computedHash;
        try {
            computedHash = computeHash(password, salt);
        } catch (IllegalArgumentException ex) {
            throw new InvalidHashException("Invalid salt format", ex);
        }


        byte[] computedHashBytes = extractHash(computedHash).getBytes(StandardCharsets.UTF_8);
        byte[] extractedHashBytes = extractHash(hash).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(computedHashBytes, extractedHashBytes);
    }

    protected final String randomSalt() {
        StringBuilder sb = new StringBuilder(saltLength);
        for (int i = 0; i < saltLength; i++) {
            sb.append(B64_ALPHABET.charAt(secureRandom.nextInt(B64_ALPHABET.length())));
        }
        return sb.toString();
    }

    /**
     * Compute the actual password hash
     *
     * @param password the password to use
     * @param salt     the salt to use (in proper crypt format)
     * @return the full password hash string
     */
    protected abstract String computeHash(String password, String salt);

    /**
     * Get the full salt, consisting of the ID, optional rounds, and the salt itself
     *
     * @return the full salt
     */
    protected abstract String getSalt();

    /**
     * Extract the full salt from a hash
     *
     * @param hash the hash to extract the salt from
     * @return the full salt containg id, rounds, and the salt itself
     * @throws InvalidHashException if the hash is incorrectly formatted
     */
    private String extractSalt(String hash) throws InvalidHashException {
        try {
            int lastDollar = hash.lastIndexOf('$');
            return hash.substring(0, lastDollar);
        } catch (IndexOutOfBoundsException ex) {
            throw new InvalidHashException("Invalid hash format", ex);
        }
    }

    /**
     * Extract the actual hash from an encoded hash string
     *
     * @param hash the hash string to extract from
     * @return the hash data
     * @throws InvalidHashException if the hash is incorrectly formatted
     */
    private String extractHash(String hash) throws InvalidHashException {
        try {
            return hash.substring(hash.lastIndexOf('$') + 1);
        } catch (IndexOutOfBoundsException ex) {
            throw new InvalidHashException("Invalid hash format", ex);
        }
    }
}
