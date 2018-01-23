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
}
