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
package de.slevermann.pwhash.pbkdf2;

import de.slevermann.pwhash.InvalidHashException;

/**
 * A strategy implementation using PBKDF2WithHmacSHA1 for password hashing.
 *
 * @author Simon Levermann
 */
public class Pbkdf2WithHmacSha1Strategy extends Pbkdf2Strategy {
    private static final String PBKDF_ALGORITHM = "PBKDF2WithHmacSHA1";
    public static final int DEFAULT_HASH_LENGTH = 20;

    /**
     * Construct a default PBKDF2WithHmacSHA1 instance
     */
    public Pbkdf2WithHmacSha1Strategy() {
        this(Pbkdf2Strategy.DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH, Pbkdf2Strategy.DEFAULT_ITERATIONS);
    }

    /**
     * @param saltLength length of the salt to generate
     * @param dkLength   length of the generated hash
     * @param iterations amount of iterations
     */
    private Pbkdf2WithHmacSha1Strategy(int saltLength, int dkLength, int iterations) {
        super(saltLength, dkLength, iterations, PBKDF_ALGORITHM);
    }

    /**
     * Acquire a custom PBKDF2WithHmacSHA1 instance
     *
     * @param saltLength length of the salt to be generated (in bytes)
     * @param dkLength   length of the hash output (in bytes)
     * @param iterations amount of iterations
     * @return a newly constructed PBKDF2WithHmacSHA1 instance
     * @throws InvalidHashException if dkLength is &gt; 20. This is because for password hashing, PBKDF dklength should
     *                              never exceed the output length of the underlying hash function.
     */
    public static Pbkdf2WithHmacSha1Strategy getInstance(int saltLength, int dkLength, int iterations) throws InvalidHashException {
        if (dkLength > 20) {
            throw new InvalidHashException("dkLength cannot be larger than output length of the hash function.");
        }

        if (saltLength <= 0) {
            throw new InvalidHashException("SaltLength must be > 0");
        }

        if (dkLength <= 0) {
            throw new InvalidHashException("dkLength must be > 0");
        }

        if (iterations <= 0) {
            throw new InvalidHashException("Iteration count must be > 0");
        }
        return new Pbkdf2WithHmacSha1Strategy(saltLength, dkLength, iterations);
    }
}
