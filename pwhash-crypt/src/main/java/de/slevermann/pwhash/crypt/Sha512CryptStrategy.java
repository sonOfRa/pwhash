package de.slevermann.pwhash.crypt;

import org.apache.commons.codec.digest.Sha2Crypt;

import java.nio.charset.StandardCharsets;

/**
 * Implementation for Sha512Crypt
 *
 * @author Simon Levermann
 */
public class Sha512CryptStrategy extends ShaCryptStrategy {

    private static final String ID = "6";

    /**
     * Create a default Sha512Crypt instance.
     * <p>
     * Uses the default 5000 rounds and a 16 byte salt. Does not encode the rounds parameter into the output
     */
    public Sha512CryptStrategy() {
        super(ID);
    }

    /**
     * Create a custom Sha512Crypt instance.
     * <p>
     * Encodes the rounds parameter into the output
     *
     * @param rounds     the amount of rounds between 1000 and 999,999,999. Smaller larger values are adjusted.
     * @param saltLength length of the salt to use. Lengths longer than 16 result in only the first 16 bytes being used
     */
    public Sha512CryptStrategy(int rounds, int saltLength) {
        super(ID, rounds, saltLength);
    }

    @Override
    protected String computeHash(String password, String salt) {
        return Sha2Crypt.sha512Crypt(password.getBytes(StandardCharsets.UTF_8), salt);
    }
}
