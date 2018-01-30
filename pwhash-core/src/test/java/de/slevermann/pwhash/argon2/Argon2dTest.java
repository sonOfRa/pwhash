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

public class Argon2dTest extends Argon2Test {
    Argon2dTest() {
        this.id = "argon2d";
        this.defaultStrategy = new Argon2dStrategy();
        this.customStrategy = new Argon2dStrategy(CUSTOM_MEMORY_COST, CUSTOM_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customMStrategy = new Argon2dStrategy(CUSTOM_MEMORY_COST,
                Argon2Strategy.DEFAULT_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customPStrategy = new Argon2dStrategy(Argon2Strategy.DEFAULT_MEMORY_COST,
                CUSTOM_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customTStrategy = new Argon2dStrategy(Argon2Strategy.DEFAULT_MEMORY_COST,
                Argon2Strategy.DEFAULT_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }
}
