package de.slevermann.pwhash.argon2;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

public abstract class Argon2Test {
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";
    protected static final int CUSTOM_MEMORY_COST = Argon2Strategy.DEFAULT_MEMORY_COST * 2;
    protected static final int CUSTOM_PARALLELISM = Argon2Strategy.DEFAULT_PARALLELISM * 2;
    protected static final int CUSTOM_TIME_COST = Argon2Strategy.DEFAULT_TIME_COST * 2;

    protected Argon2Strategy defaultStrategy;
    protected Argon2Strategy customStrategy;

    protected Argon2Strategy customMStrategy;
    protected Argon2Strategy customPStrategy;
    protected Argon2Strategy customTStrategy;

    protected String id;

    @Test
    public void defaultType() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.verify(PASSWORD, hash), "Password should match");

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], id, "Identifer should be " + id);

        Map<String, Integer> options = new HashMap<>();

        for (String option : chunks[3].split(",")) {
            String[] splitOpts = option.split("=");
            options.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        Assert.assertEquals((int) options.get("m"), Argon2Strategy.DEFAULT_MEMORY_COST,
                "Memory cost should be default");
        Assert.assertEquals((int) options.get("p"), Argon2Strategy.DEFAULT_PARALLELISM,
                "Parallelism should be default");
        Assert.assertEquals((int) options.get("t"), Argon2Strategy.DEFAULT_TIME_COST,
                "Time cost should be default");
    }

    @Test
    public void wrongPassword() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertFalse(defaultStrategy.verify("WRONG", hash), "Invalid password should fail to verify");
    }

    @Test
    public void customParameters() {
        String hash = customStrategy.hash(PASSWORD);

        Assert.assertTrue(customStrategy.verify(PASSWORD, hash), "Password should match");

        Map<String, Integer> options = new HashMap<>();

        String[] chunks = hash.split("\\$");
        for (String option : chunks[3].split(",")) {
            String[] splitOpts = option.split("=");
            options.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        Assert.assertEquals((int) options.get("m"), CUSTOM_MEMORY_COST,
                "Memory cost should be custom value");
        Assert.assertEquals((int) options.get("p"), CUSTOM_PARALLELISM,
                "Parallelism should be custom value");
        Assert.assertEquals((int) options.get("t"), CUSTOM_TIME_COST,
                "Time cost should be custom value");
    }

    @Test
    public void noRehash() {
        String hash = defaultStrategy.hash(PASSWORD);
        Assert.assertFalse(defaultStrategy.needsRehash(PASSWORD, hash),
                "Default strategy should not need rehash");
        Assert.assertFalse(defaultStrategy.needsRehash("WRONG", hash),
                "Incorrect password should not need rehash");
    }

    @Test
    public void needRehash() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(customMStrategy.needsRehash(PASSWORD, hash),
                "Custom memory cost should require rehash");
        Assert.assertTrue(customPStrategy.needsRehash(PASSWORD, hash),
                "Custom parallelism should require rehash");
        Assert.assertTrue(customTStrategy.needsRehash(PASSWORD, hash),
                "Custom time cost should require rehash");
    }
}
