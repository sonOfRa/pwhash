package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.InvalidHashException;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.testng.Assert;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;

public abstract class ShaCryptTest {

    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";
    ShaCryptStrategy defaultStrategy;
    ShaCryptStrategy customRoundsStrategy;
    ShaCryptStrategy customSaltStrategy;

    protected abstract Object[][] externalHashes();

    protected abstract Object[][] invalidSaltCharacters();

    protected abstract Object[][] badSaltId();

    @Test(dataProvider = "externalHashes")
    public void verifyExternal(String password, String hash) throws InvalidHashException {
        Assert.assertTrue(defaultStrategy.verify(password, hash),
                "External hashes should verify successfully");
    }

    @Test(dataProvider = "externalHashes", dependsOnMethods = "verifyExternal")
    public void verifyExternalWrongPassword(String password, String hash) throws InvalidHashException {
        Assert.assertFalse(defaultStrategy.verify(password + "wrong", hash),
                "External hashes should fail to verify with incorrect password");
    }

    @Test
    public void verifyInternal() throws InvalidHashException {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.verify(PASSWORD, hash),
                "Correct password should properly verify");
    }

    @Test
    public void verifyInternalWrongPassword() throws InvalidHashException {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertFalse(defaultStrategy.verify(PASSWORD + "wrong", hash),
                "Invalid password should fail to verify");
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "Invalid salt format")
    public void verifyInvalidSaltId() throws InvalidHashException {
        defaultStrategy.verify(PASSWORD, "$invalid$");
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "Invalid salt format",
            dataProvider = "invalidSaltCharacters")
    public void verifyInvalidSaltCharacters(String invalidSaltCharacters) throws InvalidHashException {
        defaultStrategy.verify(PASSWORD, invalidSaltCharacters);
    }

    @Test(expectedExceptions = InvalidHashException.class, expectedExceptionsMessageRegExp = "Invalid salt format",
            dataProvider = "badSaltId")
    public void verifyBadSaltId(String badSaltId) throws InvalidHashException {
        defaultStrategy.verify(PASSWORD, badSaltId);
    }
}
