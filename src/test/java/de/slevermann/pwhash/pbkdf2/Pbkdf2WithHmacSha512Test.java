package de.slevermann.pwhash.pbkdf2;

import de.slevermann.pwhash.InvalidHashException;
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