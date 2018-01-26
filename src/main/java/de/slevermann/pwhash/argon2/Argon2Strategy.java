package de.slevermann.pwhash.argon2;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.slevermann.pwhash.HashStrategy;

import java.util.HashMap;
import java.util.Map;

/**
 * A strategy implementation using argon2 for password hashing.
 * <p>
 * By default, argon2id is used, with reasonable parameters taken from the defaults
 * that PHP uses for its password_hash() API. All values can be adjusted.
 */
public abstract class Argon2Strategy implements HashStrategy {


    /**
     * Amount of memory used in kibibytes
     */
    public static final int DEFAULT_MEMORY_COST = 1 << 10;

    /**
     * Number of threads used
     */
    public static final int DEFAULT_PARALLELISM = 2;

    /**
     * Number of iterations
     */
    public static final int DEFAULT_TIME_COST = 2;

    /**
     * Length of the generated salt in bytes
     */
    public static final int DEFAULT_SALT_LENGTH = 16;

    /**
     * Length of the hash output in bytes
     */
    public static final int DEFAULT_HASH_LENGTH = 32;

    protected int memoryCost;

    protected int parallelism;

    protected int timeCost;

    protected Argon2 argon2;

    /**
     * Construct a fully customized hashing instance.
     * <p>
     * For all arguments, there are default values present in the class to be used if not all values need to be customized
     *
     * @param memoryCost  the memory cost in kibibytes
     * @param parallelism the amount of threads to use
     * @param timeCost    the amount of iterations to use
     */
    public Argon2Strategy(int memoryCost, int parallelism, int timeCost) {
        this.memoryCost = memoryCost;
        this.parallelism = parallelism;
        this.timeCost = timeCost;
    }

    public String hash(String password) {
        return argon2.hash(timeCost, memoryCost, parallelism, password);
    }

    public boolean verify(String password, String hash) {
        return argon2.verify(hash, password);
    }

    public boolean needsRehash(String password, String hash) {
        /*
         * If the passwords don't match, we do not rehash
         */
        if (!verify(password, hash)) {
            return false;
        }

        String[] chunks = hash.split("\\$");

        /*
         * Extract parameters and then check if they match
         */
        Map<String, Integer> options = new HashMap<>();
        for (String option : chunks[3].split(",")) {
            String[] splitOpts = option.split("=");
            options.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        return options.get("m") != this.memoryCost
                || options.get("p") != this.parallelism
                || options.get("t") != this.timeCost;
    }

    /**
     * @return the default argon2 instance, which is argon2id
     */
    public static Argon2Strategy getDefault() {
        return new Argon2idStrategy();
    }
}
