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
package de.slevermann.pwhash;

import de.slevermann.pwhash.argon2.Argon2Strategy;
import de.slevermann.pwhash.argon2.Argon2dStrategy;
import de.slevermann.pwhash.argon2.Argon2iStrategy;
import de.slevermann.pwhash.argon2.Argon2idStrategy;
import de.slevermann.pwhash.pbkdf2.Pbkdf2Strategy;
import de.slevermann.pwhash.pbkdf2.Pbkdf2WithHmacSha1Strategy;
import de.slevermann.pwhash.pbkdf2.Pbkdf2WithHmacSha256Strategy;
import de.slevermann.pwhash.pbkdf2.Pbkdf2WithHmacSha512Strategy;
import org.testng.annotations.DataProvider;

import java.util.ArrayList;
import java.util.List;

public class MigrationProvider {
    private static final int CUSTOM_ARGON2_MEMORY_COST = Argon2Strategy.DEFAULT_MEMORY_COST * 2;
    private static final int CUSTOM_ARGON2_PARALLELISM = Argon2Strategy.DEFAULT_PARALLELISM * 2;
    private static final int CUSTOM_ARGON2_TIME_COST = Argon2Strategy.DEFAULT_TIME_COST * 2;

    private static final int CUSTOM_BCRYPT_WORKFACTOR = BCryptStrategy.DEFAULT_WORK_FACTOR + 2;

    private static final int CUSTOM_PBKDF2_ITERATIONS = Pbkdf2Strategy.DEFAULT_ITERATIONS * 2;

    private HashStrategy[] defaultStrategies = new HashStrategy[]{
            new Argon2idStrategy(),
            new Argon2dStrategy(),
            new Argon2iStrategy(),
            new BCryptStrategy(),
            new Pbkdf2WithHmacSha512Strategy(),
            new Pbkdf2WithHmacSha256Strategy(),
            new Pbkdf2WithHmacSha1Strategy(),
    };

    private HashStrategy[] customStrategies = new HashStrategy[]{
            new Argon2idStrategy(CUSTOM_ARGON2_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM,
                    Argon2Strategy.DEFAULT_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),
            new Argon2idStrategy(Argon2Strategy.DEFAULT_MEMORY_COST, CUSTOM_ARGON2_PARALLELISM,
                    Argon2Strategy.DEFAULT_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),
            new Argon2idStrategy(Argon2Strategy.DEFAULT_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM,
                    CUSTOM_ARGON2_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),

            new Argon2iStrategy(CUSTOM_ARGON2_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM,
                    Argon2Strategy.DEFAULT_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),
            new Argon2iStrategy(Argon2Strategy.DEFAULT_MEMORY_COST, CUSTOM_ARGON2_PARALLELISM,
                    Argon2Strategy.DEFAULT_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),
            new Argon2iStrategy(Argon2Strategy.DEFAULT_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM,
                    CUSTOM_ARGON2_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),

            new Argon2dStrategy(CUSTOM_ARGON2_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM,
                    Argon2Strategy.DEFAULT_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),
            new Argon2dStrategy(Argon2Strategy.DEFAULT_MEMORY_COST, CUSTOM_ARGON2_PARALLELISM,
                    Argon2Strategy.DEFAULT_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),
            new Argon2dStrategy(Argon2Strategy.DEFAULT_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM,
                    CUSTOM_ARGON2_TIME_COST, Argon2Strategy.DEFAULT_SALT_LENGTH,
                    Argon2Strategy.DEFAULT_HASH_LENGTH),

            new BCryptStrategy(CUSTOM_BCRYPT_WORKFACTOR),

            Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                    Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH, CUSTOM_PBKDF2_ITERATIONS),
            Pbkdf2WithHmacSha256Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                    Pbkdf2WithHmacSha256Strategy.DEFAULT_HASH_LENGTH, CUSTOM_PBKDF2_ITERATIONS),
            Pbkdf2WithHmacSha1Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                    Pbkdf2WithHmacSha1Strategy.DEFAULT_HASH_LENGTH, CUSTOM_PBKDF2_ITERATIONS),
    };

    public MigrationProvider() throws InvalidHashException {
    }

    @DataProvider(parallel = true)
    Object[][] pairs() {
        List<Object[]> pairs = new ArrayList<>();

        for (HashStrategy from : defaultStrategies) {
            for (HashStrategy to : defaultStrategies) {
                /*
                 * Migrating between two instances of the same concrete class does not make sense.
                 * As such, we will skip all pairs formed like that
                 */
                if (from.getClass() != to.getClass()) {
                    pairs.add(new Object[]{from, to});
                }
            }
        }
        return pairs.toArray(new Object[pairs.size()][]);
    }

    @DataProvider(parallel = true)
    Object[][] customTriples() {
        List<Object[]> triples = new ArrayList<>();
        for (HashStrategy from : defaultStrategies) {
            for (HashStrategy to : defaultStrategies) {
                /*
                 * Migrating between two instances of the same concrete class does not make sense.
                 * As such, we will skip all pairs formed like that
                 */
                if (from.getClass() != to.getClass()) {
                    for (HashStrategy custom : customStrategies) {
                        /*
                         * Here, we want a custom strategy that has *the same type* as our
                         * "to-strategy". This lets us test whether a password needs to be rehashed
                         * if it was hashed with the same *type* of strategy as our to-strategy, but with
                         * different parameters
                         */
                        if (custom.getClass() == to.getClass()) {
                            triples.add(new Object[]{from, to, custom});
                        }
                    }
                }
            }
        }
        return triples.toArray(new Object[triples.size()][]);
    }
}
