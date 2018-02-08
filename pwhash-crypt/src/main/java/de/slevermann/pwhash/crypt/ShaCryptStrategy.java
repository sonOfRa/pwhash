package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.InvalidHashException;

import java.nio.charset.StandardCharsets;

/**
 * Common code for Sha512 and Sha256Crypt
 */
public abstract class ShaCryptStrategy extends CryptStrategy {
    public static final int DEFAULT_ROUNDS = 5000;
    protected int rounds;
    protected boolean outputRounds;
    protected final String id;

    /**
     * Create a default shacrypt strategy with the given ID
     * <p>
     * Does not encode the rounds parameter into the output
     *
     * @param id the ID to use
     */
    protected ShaCryptStrategy(String id) {
        super(DEFAULT_SALT_LENGTH);
        this.rounds = DEFAULT_ROUNDS;
        this.outputRounds = false;
        this.id = id;
    }

    /**
     * Create a custom shacrypt strategy
     *
     * @param id         the ID to use
     * @param rounds     the amount of iterations
     * @param saltLength length of the salt
     */
    protected ShaCryptStrategy(String id, int rounds, int saltLength) {
        super(saltLength);
        this.rounds = rounds;
        this.outputRounds = true;
        this.id = id;
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        try {
            if (!verify(password, hash)) {
                return false;
            }
        } catch (InvalidHashException ex) {
            return false;
        }

        String[] chunks = hash.split("\\$");

        int chunkCount = chunks.length;

        int saltOffset = 2;
        // If we don't have rounds encoded in the hash, but the strategy wants to encode rounds, rehash
        if (chunkCount == 4) {
            if (outputRounds) {
                return true;
            }
        }

        // If we have rounds encoded, but not in the strategy, we need to rehash as well
        if (chunkCount == 5) {
            if (!outputRounds) {
                return true;
            }

            int extractedRounds = Integer.parseInt(chunks[2].split("=")[1]);

            // If the rounds don't match up, rehash
            if (extractedRounds != rounds) {
                return true;
            }
            saltOffset = 3;
        }


        int extractedSaltLength = chunks[saltOffset].getBytes(StandardCharsets.UTF_8).length;

        // If the salt lengths do not match, rehash
        return extractedSaltLength != saltLength;
    }

    @Override
    protected String getSalt() {
        String salt = "$" + id + "$";
        if (outputRounds) {
            salt += "rounds=" + this.rounds + "$";
        }
        salt += randomSalt();
        return salt;
    }

}
