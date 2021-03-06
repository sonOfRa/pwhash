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

public class BCryptTest {
    private final BCryptStrategy defaultStrategy = new BCryptStrategy();
    private final BCryptStrategy customWorkFactor = BCryptStrategy.getInstance(12);
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";

    public BCryptTest() throws InvalidHashException {
    }

    @Test
    public void defaultType() {
        String hash = defaultStrategy.hash(PASSWORD);
        String[] chunks = hash.split("\\$");
        Assert.assertTrue(chunks[1].equals("2a"), "Identifier should be 2a");
        Assert.assertTrue(chunks[2].equals("10"), "Work factor should be 10");
    }

    @Test
    public void customWorkFactor() {
        String hash = customWorkFactor.hash(PASSWORD);
        String[] chunks = hash.split("\\$");
        Assert.assertTrue(chunks[2].equals("12"), "Work factor should be 12");
    }

    @Test
    public void defaultAuth() throws InvalidHashException {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.verify(PASSWORD, hash),
                "Password verification should succeed with correct password");
        Assert.assertFalse(defaultStrategy.verify("wrong", hash),
                "Password verification should fail with incorrect password");
    }

    @Test
    public void noRehash() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertFalse(defaultStrategy.needsRehash(PASSWORD, hash),
                "Default hash should not require a rehash");
    }

    @Test
    public void rehashWrongPassword() {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertFalse(defaultStrategy.needsRehash("wrong", hash),
                "Invalid password should not require rehash");
    }

    @Test
    public void rehash() {
        String hash = customWorkFactor.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.needsRehash(PASSWORD, hash),
                "Bigger work factor should require rehash");
    }

    @Test
    public void rehashInvalidHash() {
        String hash = "NOTAHASH";

        Assert.assertFalse(defaultStrategy.needsRehash(PASSWORD, hash),
                "Invalid hash should not warrant a rehash");
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void invalidHash() throws InvalidHashException {
        String hash = "NOTAHASH";
        defaultStrategy.verify(PASSWORD, hash);
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void smallWorkFactor() throws InvalidHashException {
        BCryptStrategy.getInstance(0);
    }

    @Test(expectedExceptions = InvalidHashException.class)
    public void largeWorkFactor() throws InvalidHashException {
        BCryptStrategy.getInstance(31);
    }
}
