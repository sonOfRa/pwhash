package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.InvalidHashException;
import org.testng.Assert;
import org.testng.annotations.Test;

public abstract class ShaCryptTest {

    ShaCryptStrategy s;

    protected abstract Object[][] externalHashes();

    @Test(dataProvider = "externalHashes")
    public void verifyExternal(String password, String hash) throws InvalidHashException {
        Assert.assertTrue(s.verify(password, hash),
                "External hashes should verify successfully");
    }

    @Test(dataProvider = "externalHashes", dependsOnMethods = "verifyExternal")
    public void verifyExternalWrongPassword(String password, String hash) throws InvalidHashException {
        Assert.assertFalse(s.verify(password + "wrong", hash),
                "External hashes should fail to verify with incorrect password");
    }

}
