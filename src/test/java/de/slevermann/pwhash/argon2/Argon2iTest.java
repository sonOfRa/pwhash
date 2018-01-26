package de.slevermann.pwhash.argon2;

public class Argon2iTest extends Argon2Test {

    Argon2iTest() {
        this.id = "argon2i";
        this.defaultStrategy = new Argon2iStrategy();
        this.customStrategy = new Argon2iStrategy(CUSTOM_MEMORY_COST, CUSTOM_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customMStrategy = new Argon2iStrategy(CUSTOM_MEMORY_COST,
                Argon2Strategy.DEFAULT_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customPStrategy = new Argon2iStrategy(Argon2Strategy.DEFAULT_MEMORY_COST,
                CUSTOM_PARALLELISM, Argon2Strategy.DEFAULT_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        this.customTStrategy = new Argon2iStrategy(Argon2Strategy.DEFAULT_MEMORY_COST,
                Argon2Strategy.DEFAULT_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
    }
}
