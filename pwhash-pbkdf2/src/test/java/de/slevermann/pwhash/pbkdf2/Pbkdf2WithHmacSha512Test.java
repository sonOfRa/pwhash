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
import de.slevermann.pwhash.pbkdf2.Pbkdf2Strategy;
import de.slevermann.pwhash.pbkdf2.Pbkdf2WithHmacSha512Strategy;
import org.testng.annotations.Test;

public class Pbkdf2WithHmacSha512Test {

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "dkLength cannot be larger.*")
    public void highDkLength() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH, 65,
                Pbkdf2Strategy.DEFAULT_ITERATIONS);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "dkLength must be > 0")
    public void negativeDkLength() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH, -1,
                Pbkdf2Strategy.DEFAULT_ITERATIONS);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "dkLength must be > 0")
    public void zeroDkLength() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH, 0,
                Pbkdf2Strategy.DEFAULT_ITERATIONS);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "SaltLength must be > 0")
    public void negativeSaltLength() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(-1, Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH,
                Pbkdf2Strategy.DEFAULT_ITERATIONS);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "SaltLength must be > 0")
    public void zeroSaltLength() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(0, Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH,
                Pbkdf2Strategy.DEFAULT_ITERATIONS);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "Iteration count must be > 0")
    public void negativeIterationCount() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH, -1);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "Iteration count must be > 0")
    public void zeroIterationCount() throws InvalidHashException {
        Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH, 0);
    }

}
