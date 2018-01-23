package de.slevermann.pwhash;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class BCryptTest {
    private static BCryptStrategy defaultStrategy;

    @BeforeClass
    public static void setUp() {
        defaultStrategy = new BCryptStrategy();
    }

    @Test
    public static void defaultType() {
        String hash = defaultStrategy.hash("The Magic Words are Squeamish Ossifrage");
        Assert.assertTrue(hash.startsWith("$2a"), "Password hash should start with $2a");
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
    public static void noRehash() {
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

    @Test
    public static void rehash() {
        String password = "The Magic Words are Squeamish Ossifrage";
        String hash = new BCryptStrategy(12).hash(password);

        Assert.assertTrue(defaultStrategy.needsRehash(password, hash),
                "Bigger work factor should require rehash");
    }

}
