package de.slevermann.pwhash.argon2;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class Argon2Test {
    private static Argon2Strategy defaultStrategy;

    @BeforeClass
    public static void setUp() {
        defaultStrategy = new Argon2Strategy();
    }

    @Test
    public static void defaultType() {
        String hash = defaultStrategy.hash("The Magic Words are Squeamish Ossifrage");
        Assert.assertTrue(hash.startsWith("$argon2id"), "Password hash should start with $argon2id");
    }

    @Test
    public static void defaultAuth() {
        String password = "The Magic Words are Squeamish Ossifrage";
        String hash = defaultStrategy.hash(password);

        Assert.assertTrue(defaultStrategy.verify(password, hash),
                "Password verification should succeed with correct password");
        Assert.assertFalse(defaultStrategy.verify("wrong", hash),
                "Password verification should fail with incorrect password");
    }

    @Test
    public static void rehash() {
        String password = "The Magic Words are Squeamish Ossifrage";
        String hash = defaultStrategy.hash(password);

        Assert.assertFalse(defaultStrategy.needsRehash(password, hash),
                "Default hash should not require a rehash");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public static void rehashException() {
        String password = "The Magic Words are Squeamish Ossifrage";
        String hash = defaultStrategy.hash(password);

        defaultStrategy.needsRehash("wrong", hash);
    }
}
