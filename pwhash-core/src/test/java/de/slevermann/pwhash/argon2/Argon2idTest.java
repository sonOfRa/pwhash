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

import de.slevermann.pwhash.InvalidHashException;
import org.testng.Assert;
import org.testng.annotations.Test;

public class Argon2idTest extends Argon2Test {

    Argon2idTest() throws InvalidHashException {
        this.id = "argon2id";
        this.defaultStrategy = new Argon2idStrategy();
        this.customStrategy = Argon2idStrategy.getInstance(CUSTOM_MEMORY_COST, CUSTOM_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customMStrategy = Argon2idStrategy.getInstance(CUSTOM_MEMORY_COST,
                Argon2Strategy.DEFAULT_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customPStrategy = Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_MEMORY_COST,
                CUSTOM_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customTStrategy = Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_MEMORY_COST,
                Argon2Strategy.DEFAULT_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }

    @Test
    public void checkDefault() {
        Assert.assertTrue(Argon2Strategy.getDefault() instanceof Argon2idStrategy,
                "Default strategy type should be id");
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void badMemoryCost() throws InvalidHashException {
        Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_PARALLELISM * 4, Argon2Strategy.DEFAULT_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void badParallelism() throws InvalidHashException {
        Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_MEMORY_COST, 0, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void badTimeCost() throws InvalidHashException {
        Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM, 0,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void badSaltLength() throws InvalidHashException {
        Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                7, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void badHashLength() throws InvalidHashException {
        Argon2idStrategy.getInstance(Argon2Strategy.DEFAULT_MEMORY_COST, Argon2Strategy.DEFAULT_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, 3);
    }
}
