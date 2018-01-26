package de.slevermann.pwhash;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.util.HashMap;
import java.util.Map;

/**
 * A strategy implementation using argon2 for password hashing.
 * <p>
 * By default, argon2id is used, with reasonable parameters taken from the defaults
 * that PHP uses for its password_hash() API. All values can be adjusted.
 */
public class Argon2Strategy implements HashStrategy {


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

    /**
     * PHP uses Argon2i, but the internet draft recommends argon2id, which didn't exist when PHP picked argon2i
     */
    public static final Argon2Factory.Argon2Types DEFAULT_TYPE = Argon2Factory.Argon2Types.ARGON2id;

    private int memoryCost;

    private int parallelism;

    private int timeCost;

    private Argon2Factory.Argon2Types type;

    private Argon2 argon2;

    /**
     * Construct an instance with all defaults
     */
    public Argon2Strategy() {
        this(DEFAULT_TYPE, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    }

    /**
     * Construct an instance with default parameters, except the argon2 type
     *
     * @param type the type of argon2 (i, id, d) to use
     */
    public Argon2Strategy(Argon2Factory.Argon2Types type) {
        this(type, DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    }

    /**
     * Construct a fully customized hashing instance.
     * <p>
     * For all arguments, there are default values present in the class to be used if not all values need to be customized
     *
     * @param type        the type of argon2 (i, id, d) to use
     * @param memoryCost  the memory cost in kibibytes
     * @param parallelism the amount of threads to use
     * @param timeCost    the amount of iterations to use
     * @param saltLength  the length of the salt
     * @param hashLength  the length of the hash
     */
    public Argon2Strategy(Argon2Factory.Argon2Types type, int memoryCost, int parallelism, int timeCost,
                          int saltLength, int hashLength) {
        this.type = type;
        this.memoryCost = memoryCost;
        this.parallelism = parallelism;
        this.timeCost = timeCost;
        this.argon2 = Argon2Factory.create(type, saltLength, hashLength);
    }

    public String hash(String password) {
        return argon2.hash(timeCost, memoryCost, parallelism, password);
    }

    public boolean verify(String password, String hash) {
        return argon2.verify(hash, password);
    }

    public boolean needsRehash(String password, String hash) {
        /*
         * If the password fails to verify against the given hash, it might not be a valid hash. Abort here.
         */
        if (!verify(password, hash)) {
            return false;
        }

        String[] chunks = hash.split("\\$");

        /*
         * The first chunk is the name of the function used
         */
        String name = chunks[1];
        String expectedName = "INVALID";
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
        Map<String, Integer> optionMap = new HashMap<>();

        for (String option : options) {
            String[] split = option.split("=");
            optionMap.put(split[0], Integer.parseInt(split[1]));
        }

        if (optionMap.get("m") != memoryCost) {
            return true;
        }

        if (optionMap.get("p") != parallelism) {
            return true;
        }

        if (optionMap.get("t") != timeCost) {
            return true;
        }
        return false;
    }
}
