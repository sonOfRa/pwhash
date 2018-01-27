package de.slevermann.pwhash.argon2;

import de.mkammerer.argon2.Argon2Factory;

/**
 * A strategy implementation using argon2d for password hashing.
 *
 * @author Simon Levermann
 */
public class Argon2dStrategy extends Argon2Strategy {
    /**
     * Create a default argon2d instance
     */
    public Argon2dStrategy() {
        this(DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    }

    /**
     * Create a customized argon2d instance
     * <p>
     * For all arguments, there are default values present in superclass to be used if not all values need to be customized
     *
     * @param memoryCost  the memory cost in kibibytes
     * @param parallelism the amount of threads to use
     * @param timeCost    the amount of iterations to use
     * @param saltLength  the length of the generated salt
     * @param hashLength  the output length for the hash
     */
    public Argon2dStrategy(int memoryCost, int parallelism, int timeCost, int saltLength, int hashLength) {
        super(memoryCost, parallelism, timeCost);
        this.argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2d, saltLength, hashLength);
    }

}
