package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;
import org.apache.commons.codec.digest.Crypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public abstract class CryptStrategy implements HashStrategy {
    public static final int DEFAULT_SALT_LENGTH = 16;
    public static final String B64_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    protected int saltLength;

    private final SecureRandom secureRandom = new SecureRandom();

    protected CryptStrategy(int saltLength) {
        this.saltLength = saltLength;
    }

    @Override
    public String hash(String password) {
        return Crypt.crypt(password, getSalt());
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {
        String salt = extractSalt(hash);
        String computedHash = Crypt.crypt(password, salt);

        byte[] computedHashBytes = extractHash(computedHash).getBytes(StandardCharsets.UTF_8);
        byte[] extractedHashBytes = extractHash(hash).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(computedHashBytes, extractedHashBytes);
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        return false;
    }

    protected final String randomSalt() {
        StringBuilder sb = new StringBuilder(saltLength);
        for (int i = 0; i < saltLength; i++) {
            sb.append(B64_ALPHABET.charAt(secureRandom.nextInt(B64_ALPHABET.length())));
        }
        return sb.toString();
    }

    protected abstract String getSalt();

    protected abstract String extractSalt(String hash);

    protected abstract String extractHash(String hash);
}
