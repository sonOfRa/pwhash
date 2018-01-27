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
import org.testng.annotations.DataProvider;

public class Pbkdf2Provider {
    private static final int CUSTOM_ITERATION_COUNT = 30000;

    @DataProvider
    Object[][] defaultFactory() {
        return new Object[][]{
                {new Pbkdf2WithHmacSha512Strategy(), "PBKDF2WithHmacSHA512".toLowerCase()},
        };
    }

    @DataProvider
    Object[][] customFactory() throws InvalidHashException {
        return new Object[][]{
                {Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                        Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH, CUSTOM_ITERATION_COUNT), CUSTOM_ITERATION_COUNT},
        };
    }

    @DataProvider
    Object[][] needRehashFactory() throws InvalidHashException {
        return new Object[][]{
                {new Pbkdf2WithHmacSha512Strategy(),
                        Pbkdf2WithHmacSha512Strategy.getInstance(Pbkdf2Strategy.DEFAULT_SALT_LENGTH,
                        Pbkdf2WithHmacSha512Strategy.DEFAULT_HASH_LENGTH, CUSTOM_ITERATION_COUNT)},
        };
    }
}
