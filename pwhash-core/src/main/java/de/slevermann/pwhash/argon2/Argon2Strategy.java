/*
    Copyright 2018 Simon Levermann

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */
package de.slevermann.pwhash.argon2;

import de.mkammerer.argon2.Argon2;
import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;

import java.util.HashMap;
import java.util.Map;

/**
 * A strategy implementation using argon2 for password hashing.
 * <p>
 * By default, argon2id is used, with reasonable parameters taken from the defaults
 * that PHP uses for its password_hash() API. All values can be adjusted.
 *
 * @author Simon Levermann
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

    private int memoryCost;

    private int parallelism;

    private int timeCost;

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
    protected Argon2Strategy(int memoryCost, int parallelism, int timeCost) {
        this.memoryCost = memoryCost;
        this.parallelism = parallelism;
        this.timeCost = timeCost;
    }

    @Override
    public String hash(String password) {
        return argon2.hash(timeCost, memoryCost, parallelism, password);
    }

    @Override
    public boolean verify(String password, String hash) {
        return argon2.verify(hash, password);
    }

    @Override
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
     * Get a default argon2 instance
     *
     * @return the default argon2 instance, which is argon2id
     */
    public static Argon2Strategy getDefault() {
        return new Argon2idStrategy();
    }


    /**
     * Verify the given parameters for use with argon2
     *
     * @param memoryCost  the memory cost to verify, must be &gt;= 8*parallelism
     * @param parallelism the parallelism to verify, must be &gt;= 1
     * @param timeCost    the time cost to verify, must be &gt;= 1
     * @param saltLength  the salt length to verify, must be &gt;= 8
     * @param hashLength  the output length to verify, must be &gt;= 4
     * @throws InvalidHashException if any of the given parameters are illegal
     */
    public static void verifyParameters(int memoryCost, int parallelism, int timeCost, int saltLength, int hashLength)
            throws InvalidHashException {
        if (memoryCost < 8 * parallelism) {
            throw new InvalidHashException("Memory cost must be >= 8*parallelism");
        }

        if (parallelism < 1) {
            throw new InvalidHashException("Parallelism must be >= 1");
        }

        if (timeCost < 1) {
            throw new InvalidHashException("Time cost must be >= 1");
        }

        if (saltLength < 8) {
            throw new InvalidHashException("Salt must be at least 8 bytes long");
        }

        if (hashLength < 4) {
            throw new InvalidHashException("Hash must be at least 4 bytes long");
        }
    }
}
