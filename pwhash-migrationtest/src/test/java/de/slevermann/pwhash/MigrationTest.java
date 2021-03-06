/*
    Copyright 2018 Simon Levermann

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */
package de.slevermann.pwhash;


import org.testng.Assert;
import org.testng.annotations.Test;

@Test(dataProviderClass = MigrationProvider.class)
public class MigrationTest {
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";

    @Test(dataProvider = "pairs")
    public void useNewFormat(HashStrategy from, HashStrategy to) throws InvalidHashException {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String hash = m.hash(PASSWORD);

        Assert.assertTrue(m.verify(PASSWORD, hash), "MigrationStrategy should verify password correctly");
        Assert.assertTrue(to.verify(PASSWORD, hash), "MigrationStrategy should use new password format");

        boolean result;

        try {
            result = from.verify(PASSWORD, hash);
        } catch (InvalidHashException ex) {
            result = false;
        }

        Assert.assertFalse(result, "Old Strategy should fail to verify password generated by MigrationStrategy");
    }

    @Test(dataProvider = "pairs")
    public void verifyOldFormat(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String oldHash = from.hash(PASSWORD);

        Assert.assertTrue(m.verify(PASSWORD, oldHash),
                "MigrationStrategy should successfully verify old hashes");
    }

    @Test(dataProvider = "pairs")
    public void wrongPassword(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);
        String hash = m.hash(PASSWORD);

        Assert.assertFalse(m.verify("WRONG", hash),
                "MigrationStrategy should reject invalid passwords");
    }

    @Test(dataProvider = "pairs")
    public void invalidHash(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);
        Assert.assertFalse(m.verify(PASSWORD, "NOTAHASH"),
                "MigrationStrategy should reject invalid hash");
    }

    @Test(dataProvider = "pairs")
    public void noRehashWrongPassword(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String hash = m.hash(PASSWORD);
        Assert.assertFalse(m.needsRehash("WRONG", hash),
                "Invalid password should not require rehash");
    }

    @Test(dataProvider = "pairs")
    public void noRehashInvalidHash(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        Assert.assertFalse(m.needsRehash(PASSWORD, "NOTAHASH"),
                "Invalid hash should not require rehash");
    }

    @Test(dataProvider = "pairs")
    public void noRehashNew(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String newHash = to.hash(PASSWORD);
        Assert.assertFalse(m.needsRehash(PASSWORD, newHash),
                "New hash should not require rehash");
    }

    @Test(dataProvider = "pairs")
    public void needRehashOld(HashStrategy from, HashStrategy to) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String oldHash = from.hash(PASSWORD);

        Assert.assertTrue(m.needsRehash(PASSWORD, oldHash),
                "Old format hash should require rehash");
    }

    @Test(dataProvider = "customTriples")
    public void verifyCustomHash(HashStrategy from, HashStrategy to, HashStrategy custom) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String customHash = custom.hash(PASSWORD);
        Assert.assertTrue(m.verify(PASSWORD, customHash),
                "MigrationStrategy should successfully verify custom new hashes");
    }

    @Test(dataProvider = "customTriples")
    public void rehashCustomHash(HashStrategy from, HashStrategy to, HashStrategy custom) {
        MigrationStrategy m = new MigrationStrategy(from, to);

        String customHash = custom.hash(PASSWORD);
        Assert.assertTrue(m.needsRehash(PASSWORD, customHash),
                "Custom new hashes should require rehash");
    }
}
