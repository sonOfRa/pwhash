package de.slevermann.pwhash;

import de.mkammerer.argon2.Argon2Factory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;

public class Argon2Test {
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";
    private static Argon2Strategy defaultStrategy;

    @BeforeClass
    public static void setUp() {
        defaultStrategy = new Argon2Strategy();
    }

    @Test
    public static void defaultType() {
        String hash = defaultStrategy.hash(PASSWORD);

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], "argon2id", "Identifier should be argon2id");

        String[] options = chunks[3].split(",");

        Map<String, Integer> optionMap = new HashMap<>();
        for (String option : options) {
            String[] splitOpts = option.split("=");
            optionMap.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        Assert.assertEquals((int) optionMap.get("m"), Argon2Strategy.DEFAULT_MEMORY_COST, "Memory cost should be default");
        Assert.assertEquals((int) optionMap.get("p"), Argon2Strategy.DEFAULT_PARALLELISM, "Thread count should be default");
        Assert.assertEquals((int) optionMap.get("t"), Argon2Strategy.DEFAULT_TIME_COST, "Time cost should be default");
    }

    @Test
    public static void defaultDType() {
        Argon2Strategy dStrategy = new Argon2Strategy(Argon2Factory.Argon2Types.ARGON2d);
        String hash = dStrategy.hash(PASSWORD);

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], "argon2d", "Identifier should be argon2d");

        String[] options = chunks[3].split(",");

        Map<String, Integer> optionMap = new HashMap<>();
        for (String option : options) {
            String[] splitOpts = option.split("=");
            optionMap.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        Assert.assertEquals((int) optionMap.get("m"), Argon2Strategy.DEFAULT_MEMORY_COST, "Memory cost should be default");
        Assert.assertEquals((int) optionMap.get("p"), Argon2Strategy.DEFAULT_PARALLELISM, "Thread count should be default");
        Assert.assertEquals((int) optionMap.get("t"), Argon2Strategy.DEFAULT_TIME_COST, "Time cost should be default");
    }

    @Test
    public static void defaultIType() {
        Argon2Strategy iStrategy = new Argon2Strategy(Argon2Factory.Argon2Types.ARGON2i);
        String hash = iStrategy.hash(PASSWORD);

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], "argon2i", "Identifier should be argon2i");

        String[] options = chunks[3].split(",");

        Map<String, Integer> optionMap = new HashMap<>();
        for (String option : options) {
            String[] splitOpts = option.split("=");
            optionMap.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        Assert.assertEquals((int) optionMap.get("m"), Argon2Strategy.DEFAULT_MEMORY_COST, "Memory cost should be default");
        Assert.assertEquals((int) optionMap.get("p"), Argon2Strategy.DEFAULT_PARALLELISM, "Thread count should be default");
        Assert.assertEquals((int) optionMap.get("t"), Argon2Strategy.DEFAULT_TIME_COST, "Time cost should be default");
    }

    @Test
    public static void customInstance() {
        Argon2Factory.Argon2Types type = Argon2Factory.Argon2Types.ARGON2d;
        int memoryCost = 2048;
        int parallelism = 4;
        int timeCost = 4;
        int saltLength = 32;
        int hashLength = 64;
        Argon2Strategy customStrategy = new Argon2Strategy(type, memoryCost, parallelism, timeCost, saltLength, hashLength);

        String hash = customStrategy.hash(PASSWORD);

        Assert.assertTrue(customStrategy.verify(PASSWORD, hash), "Password should match");

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], "argon2d", "Identifier should be argon2d");

        String[] options = chunks[3].split(",");

        Map<String, Integer> optionMap = new HashMap<>();
        for (String option : options) {
            String[] splitOpts = option.split("=");
            optionMap.put(splitOpts[0], Integer.parseInt(splitOpts[1]));
        }

        Assert.assertEquals((int) optionMap.get("m"), memoryCost, "Memory cost should match");
        Assert.assertEquals((int) optionMap.get("p"), parallelism, "Thread count should match");
        Assert.assertEquals((int) optionMap.get("t"), timeCost, "Time cost should match");
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
    public static void rehash() {
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
}
