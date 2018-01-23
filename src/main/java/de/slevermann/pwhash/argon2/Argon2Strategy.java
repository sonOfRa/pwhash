package de.slevermann.pwhash.argon2;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.slevermann.pwhash.HashStrategy;

import java.util.HashMap;
import java.util.Map;

/**
 * A strategy implementation using argon2 for password hashing
 * <p>
 */
public class Argon2Strategy implements HashStrategy {


    /**
     * Amount of memory used in kibibytes
     */
    public static final int DEFAULT_MEMORY_COST = 1 << 10;

    /**
     * Number of threads used
     */
    public static final int DEFAULT_THREADS = 2;

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

    /**
     * PHP uses Argon2i, but the internet draft recommends argon2id, which didn't exist when PHP picked argon2i
     */
    public static final Argon2Factory.Argon2Types DEFAULT_TYPE = Argon2Factory.Argon2Types.ARGON2id;

    private int memoryCost;

    private int threads;

    private int timeCost;

    private Argon2Factory.Argon2Types type;

    private Argon2 argon2;

    public Argon2Strategy() {
        memoryCost = DEFAULT_MEMORY_COST;
        threads = DEFAULT_THREADS;
        timeCost = DEFAULT_TIME_COST;
        type = DEFAULT_TYPE;
        argon2 = Argon2Factory.create(type, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    }

    public String hash(String password) {
        return argon2.hash(timeCost, memoryCost, threads, password);
    }

    public boolean verify(String password, String hash) {
        return argon2.verify(hash, password);
    }

    public boolean needsRehash(String password, String hash) {
        /*
         * If the password fails to verify against the given hash, it might not be a valid hash. Abort here.
         */
        if (!verify(password, hash)) {
            throw new IllegalArgumentException("Cannot verify hash");
        }

        String[] chunks = hash.split("\\$");
        if (chunks.length != 6) {
            /*
             * Argon2 hashes have 6 chunks.
             * If this is not the case, the hash is not a valid argon2 hash and needs to be rehashed
             */
            return true;
        }

        /*
         * The first chunk is the name of the function used
         */
        String name = chunks[1];
        String expectedName;
        switch (type) {
            case ARGON2i:
                expectedName = "argon2i";
                break;
            case ARGON2d:
                expectedName = "argon2d";
                break;
            case ARGON2id:
                expectedName = "argon2id";
                break;
            default:
                expectedName = "INVALID";
        }

        /*
         * The stored hash does not match the expected name. That means it's either not an argon2
         * hash at all, or it's a different version, like argon2i != argon2d. This means the password
         * must be rehashed
         */
        if (!name.equals(expectedName)) {
            return true;
        }

        String[] options = chunks[3].split(",");
        Map<String, Integer> optionMap = new HashMap<String, Integer>();

        for (String option : options) {
            String[] split = option.split("=");
            optionMap.put(split[0], Integer.parseInt(split[1]));
        }

        if (optionMap.get("m") != memoryCost) {
            return true;
        }

        if (optionMap.get("p") != threads) {
            return true;
        }

        if (optionMap.get("t") != timeCost) {
            return true;
        }
        return false;
    }
}
