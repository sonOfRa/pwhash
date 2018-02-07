package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.InvalidHashException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class Sha512CryptTest {

    private Sha512CryptStrategy s = new Sha512CryptStrategy(ShaCryptStrategy.DEFAULT_ROUNDS, 16);

    @DataProvider
    Object[][] externalHashes() {
        return new Object[][]{
                {"asdfasdf", "$6$rounds=1000$PqCkJ2HWmZi$xhtd6yliKVhKPISij/3/0bBneuKQmVgv.xAqFxMZYj.fUZuurWq6hrwXXc5uIx4aDALUm2sgVuLX37OEAuQiL0"},
                {"asdfasdf", "$6$rounds=5000$Nzv1t2p2u9xgjf$8N54a/RZF9pVO7jBvjYP9bfcxTOZi6f18aWBaNxj6ZXESdAxy2PijSznH89e8ii5rNW16ifjUOff/OJLZx9wq/"},
        };
    }

    @DataProvider
    Object[][] externalIncorrectPassword() {
        return new Object[][]{
                {"wrong", "$6$rounds=1000$PqCkJ2HWmZi$xhtd6yliKVhKPISij/3/0bBneuKQmVgv.xAqFxMZYj.fUZuurWq6hrwXXc5uIx4aDALUm2sgVuLX37OEAuQiL0"},
                {"wrong", "$6$rounds=5000$Nzv1t2p2u9xgjf$8N54a/RZF9pVO7jBvjYP9bfcxTOZi6f18aWBaNxj6ZXESdAxy2PijSznH89e8ii5rNW16ifjUOff/OJLZx9wq/"},
        };
    }

    @Test(dataProvider = "externalHashes")
    public void verifyExternal(String password, String hash) throws InvalidHashException {
        Assert.assertTrue(s.verify(password, hash), "Correct password should verify successfully");
    }

    @Test(dataProvider = "externalIncorrectPassword")
    public void verifyExternalIncorrectPassword(String password, String hash) throws InvalidHashException {
        Assert.assertFalse(s.verify(password, hash), "Incorrect password should fail to verify");
    }


    @Test
    public void verifyInternal() throws InvalidHashException {
        String password = "foobar";
        String hash = s.hash(password);

        Assert.assertTrue(s.verify(password, hash));
    }
}
