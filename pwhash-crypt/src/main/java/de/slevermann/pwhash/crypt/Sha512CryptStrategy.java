package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.InvalidHashException;

/**
 * Implementation for Sha512Crypt
 */
public class Sha512CryptStrategy extends CryptStrategy {

    public static final int DEFAULT_ROUNDS = 5000;
    private int rounds;
    private boolean outputRounds;

    public Sha512CryptStrategy() {
        super(DEFAULT_SALT_LENGTH);
        this.rounds = DEFAULT_ROUNDS;
        this.outputRounds = false;
    }

    public Sha512CryptStrategy(int rounds, int saltLength) {
        super(saltLength);
        this.rounds = rounds;
        this.outputRounds = true;
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {
        return false;
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        return false;
    }

    @Override
    protected String getSalt() {
        String salt = "$6$";
        if (outputRounds) {
            salt += "rounds=" + this.rounds + "$";
        }
        salt += randomSalt();
        return salt;
    }
}
