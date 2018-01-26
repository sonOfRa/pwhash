package de.slevermann.pwhash;

import de.slevermann.pwhash.argon2.Argon2Strategy;
import de.slevermann.pwhash.argon2.Argon2idStrategy;
import org.testng.Assert;
import org.testng.annotations.Test;

public class MigrationTest {
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";

    private BCryptStrategy bCryptStrategy = new BCryptStrategy();
    private Argon2idStrategy argon2idStrategy = new Argon2idStrategy();

    private MigrationStrategy bCryptToArgon2idStrategy = new MigrationStrategy(bCryptStrategy, argon2idStrategy);
    private MigrationStrategy argon2idToBCryptStrategy = new MigrationStrategy(argon2idStrategy, bCryptStrategy);

    @Test
    public void hash() {
        String hash = bCryptToArgon2idStrategy.hash(PASSWORD);

        String[] chunks = hash.split("\\$");

        Assert.assertEquals(chunks[1], "argon2id", "Migrationstrategy should hash with new strategy");

        hash = argon2idToBCryptStrategy.hash(PASSWORD);

        chunks = hash.split("\\$");

        Assert.assertEquals(chunks[1], "2a", "Migrationstrategy should hash with new strategy");
    }

    @Test
    public void correctPassword() {
        String bcryptHash = bCryptStrategy.hash(PASSWORD);
        String argon2idHash = argon2idStrategy.hash(PASSWORD);

        Assert.assertTrue(bCryptToArgon2idStrategy.verify(PASSWORD, bcryptHash),
                "Valid password should match");
        Assert.assertTrue(bCryptToArgon2idStrategy.verify(PASSWORD, argon2idHash),
                "Valid password should match");
        Assert.assertTrue(argon2idToBCryptStrategy.verify(PASSWORD, bcryptHash),
                "Valid password should match");
        Assert.assertTrue(argon2idToBCryptStrategy.verify(PASSWORD, argon2idHash),
                "Valid password should match");
    }

    @Test
    public void incorrectPassword() {
        String bcryptHash = bCryptStrategy.hash(PASSWORD);
        String argon2idHash = argon2idStrategy.hash(PASSWORD);

        Assert.assertFalse(bCryptToArgon2idStrategy.verify("WRONG", bcryptHash),
                "Invalid password should not match");
        Assert.assertFalse(bCryptToArgon2idStrategy.verify("WRONG", argon2idHash),
                "Invalid password should not match");
        Assert.assertFalse(argon2idToBCryptStrategy.verify("WRONG", bcryptHash),
                "Invalid password should not match");
        Assert.assertFalse(argon2idToBCryptStrategy.verify("WRONG", argon2idHash),
                "Invalid password should not match");
    }

    @Test
    public void noRehashCorrectNew() {
        String bcryptHash = bCryptStrategy.hash(PASSWORD);
        String argon2idHash = argon2idStrategy.hash(PASSWORD);

        Assert.assertFalse(bCryptToArgon2idStrategy.needsRehash(PASSWORD, argon2idHash),
                "Valid new password should not require rehash");
        Assert.assertFalse(argon2idToBCryptStrategy.needsRehash(PASSWORD, bcryptHash),
                "Valid new password should not require rehash");
    }

    @Test
    public void noRehashIncorrectOld() {
        String bcryptHash = bCryptStrategy.hash(PASSWORD);
        String argon2idHash = argon2idStrategy.hash(PASSWORD);

        Assert.assertFalse(bCryptToArgon2idStrategy.needsRehash("WRONG", bcryptHash),
                "Invalid old password should not require rehash");
        Assert.assertFalse(argon2idToBCryptStrategy.needsRehash("WRONG", argon2idHash),
                "Invalid old password should not require rehash");
    }

    @Test
    public void noRehashIncorrectNew() {
        String bcryptHash = bCryptStrategy.hash(PASSWORD);
        String argon2idHash = argon2idStrategy.hash(PASSWORD);

        Assert.assertFalse(bCryptToArgon2idStrategy.needsRehash("WRONG", argon2idHash),
                "Invalid new password should not require rehash");
        Assert.assertFalse(argon2idToBCryptStrategy.needsRehash("WRONG", bcryptHash),
                "Invalid new password should not require rehash");
    }

    @Test
    public void rehashCorrectOld() {
        String bcryptHash = bCryptStrategy.hash(PASSWORD);
        String argon2idHash = argon2idStrategy.hash(PASSWORD);

        Assert.assertTrue(bCryptToArgon2idStrategy.needsRehash(PASSWORD, bcryptHash),
                "Valid old password should require rehash");
        Assert.assertTrue(argon2idToBCryptStrategy.needsRehash(PASSWORD, argon2idHash),
                "Valid old password should require rehash");
    }

    @Test
    public void rehashCustomNew() {

        Argon2idStrategy customArgon2idStrategy = new Argon2idStrategy(Argon2Strategy.DEFAULT_MEMORY_COST * 2,
                Argon2Strategy.DEFAULT_PARALLELISM * 2, Argon2Strategy.DEFAULT_TIME_COST * 2,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);
        String argon2idHash = customArgon2idStrategy.hash(PASSWORD);

        BCryptStrategy customBCryptStrategy = new BCryptStrategy(BCryptStrategy.DEFAULT_WORK_FACTOR + 2);
        String bcryptHash = customBCryptStrategy.hash(PASSWORD);

        Assert.assertTrue(bCryptToArgon2idStrategy.needsRehash(PASSWORD, argon2idHash),
                "Rehash should be required when parameters differ from MigrationStrategy");
        Assert.assertTrue(argon2idToBCryptStrategy.needsRehash(PASSWORD, bcryptHash),
                "Rehash should be required when parameters differ from MigrationStrategy");
    }
}
