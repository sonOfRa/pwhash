package de.slevermann.pwhash;

import org.mindrot.jbcrypt.BCrypt;

/**
 * A strategy implementation using bcrypt
 * <p>
 * Uses a work factor of 10 by default.
 */
public class BCryptStrategy implements HashStrategy {

    public static final int DEFAULT_WORK_FACTOR = 10;

    private int workFactor;

    /**
     * Construct a default bcrypt instance
     */
    public BCryptStrategy() {
        this(DEFAULT_WORK_FACTOR);
    }

    /**
     * Construct a bcrypt instance with a custom work factor
     *
     * @param workFactor the work factor to use
     */
    public BCryptStrategy(int workFactor) {
        this.workFactor = workFactor;
    }

    public String hash(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(workFactor));
    }

    public boolean verify(String password, String hash) {
        return BCrypt.checkpw(password, hash);
    }

    public boolean needsRehash(String password, String hash) {
        /*
         * If the password fails to verify against the given hash, it might not be a valid hash. Abort here.
         */
        if (!verify(password, hash)) {
            return false;
        }

        int workFactor = Integer.parseInt(hash.split("\\$")[2]);

        return workFactor != this.workFactor;
    }
}
