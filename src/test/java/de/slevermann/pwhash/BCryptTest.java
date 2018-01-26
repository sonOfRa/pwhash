package de.slevermann.pwhash;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class BCryptTest {
    private static final BCryptStrategy defaultStrategy = new BCryptStrategy();
    private static final BCryptStrategy customWorkFactor = new BCryptStrategy(12);
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";


    @Test
    public static void defaultType() {
        String hash = defaultStrategy.hash(PASSWORD);
        String[] chunks = hash.split("\\$");
        Assert.assertTrue(chunks[1].equals("2a"), "Identifier should be 2a");
        Assert.assertTrue(chunks[2].equals("10"), "Work factor should be 10");
    }

    @Test
    public static void customWorkFactor() {
        String hash = customWorkFactor.hash(PASSWORD);
        String[] chunks = hash.split("\\$");
        Assert.assertTrue(chunks[2].equals("12"), "Work factor should be 12");
    }

    @Test
    public static void defaultAuth() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.verify(PASSWORD, hash),
                "Password verification should succeed with correct password");
        Assert.assertFalse(defaultStrategy.verify("wrong", hash),
                "Password verification should fail with incorrect password");
    }

    @Test
    public static void noRehash() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertFalse(defaultStrategy.needsRehash(PASSWORD, hash),
                "Default hash should not require a rehash");
    }

    @Test
    public static void rehashWrongPassword() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertFalse(defaultStrategy.needsRehash("wrong", hash),
                "Invalid password should not require rehash");
    }

    @Test
    public static void rehash() {
        String hash = new BCryptStrategy(12).hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.needsRehash(PASSWORD, hash),
                "Bigger work factor should require rehash");
    }

}
