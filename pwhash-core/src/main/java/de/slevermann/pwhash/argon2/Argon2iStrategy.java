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

import de.mkammerer.argon2.Argon2Factory;

/**
 * A strategy implementation using argon2i for password hashing.
 *
 * @author Simon Levermann
 */
public class Argon2iStrategy extends Argon2Strategy {
    /**
     * Create a default argon2i instance
     */
    public Argon2iStrategy() {
        this(DEFAULT_MEMORY_COST, DEFAULT_PARALLELISM, DEFAULT_TIME_COST, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    }

    /**
     * Create a customized argon2i instance
     * <p>
     * For all arguments, there are default values present in superclass to be used if not all values need to be customized
     *
     * @param memoryCost  the memory cost in kibibytes
     * @param parallelism the amount of threads to use
     * @param timeCost    the amount of iterations to use
     * @param saltLength  the length of the generated salt
     * @param hashLength  the output length for the hash
     */
    public Argon2iStrategy(int memoryCost, int parallelism, int timeCost, int saltLength, int hashLength) {
        super(memoryCost, parallelism, timeCost);
        this.argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i, saltLength, hashLength);
    }
}
