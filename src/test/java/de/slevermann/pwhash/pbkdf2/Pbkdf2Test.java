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
package de.slevermann.pwhash.pbkdf2;

import de.slevermann.pwhash.InvalidHashException;
import org.testng.Assert;
import org.testng.annotations.Test;

@Test(dataProviderClass = Pbkdf2Provider.class)
public class Pbkdf2Test {
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";

    @Test(dataProvider = "defaultFactory")
    public void defaultType(Pbkdf2Strategy defaultStrategy, String id) throws InvalidHashException {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.verify(PASSWORD, hash), "Password should match");

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], id, "Identifer should be " + id);

        Assert.assertEquals(Integer.parseInt(chunks[2].split("=")[1]), Pbkdf2Strategy.DEFAULT_ITERATIONS,
                "Iteration count should be default");
    }

    @Test(dataProvider = "defaultFactory")
    public void wrongPassword(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = strategy.hash(PASSWORD);
        Assert.assertFalse(strategy.verify("WRONG", hash));
    }

    @Test(dataProvider = "customFactory")
    public void customParameters(Pbkdf2Strategy strategy, int iterations) {
        String hash = strategy.hash(PASSWORD);

        Assert.assertEquals(Integer.parseInt(hash.split("\\$")[2].split("=")[1]), iterations,
                "Iteration count should be custom");
    }

    @Test(dataProvider = "customFactory")
    public void customParametersWrongPassword(Pbkdf2Strategy strategy, int iterations) throws InvalidHashException {
        String hash = strategy.hash(PASSWORD);
        Assert.assertFalse(strategy.verify("WRONG", hash));
    }

    @Test(dataProvider = "defaultFactory")
    public void noRehash(Pbkdf2Strategy strategy, String id) {
        String hash = strategy.hash(PASSWORD);

        Assert.assertFalse(strategy.needsRehash(PASSWORD, hash), "Unchanged parameters should not require rehash");
    }

    @Test(dataProvider = "defaultFactory")
    public void noRehashInvalid(Pbkdf2Strategy strategy, String id) {
        Assert.assertFalse(strategy.needsRehash(PASSWORD, "INVALID"),
                "Invalid hash should not require rehash");
    }

    @Test(dataProvider = "defaultFactory")
    public void noRehashWrongPassword(Pbkdf2Strategy strategy, String id) {
        String hash = strategy.hash(PASSWORD);
        Assert.assertFalse(strategy.needsRehash("WRONG", hash),
                "Invalid password should not require rehash");
    }

    @Test(dataProvider = "needRehashFactory")
    public void needRehash(Pbkdf2Strategy defaultStrategy, Pbkdf2Strategy customStrategy) {
        String defaultHash = defaultStrategy.hash(PASSWORD);
        String customHash = customStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.needsRehash(PASSWORD, customHash),
                "Changed parameters should require rehash");
        Assert.assertTrue(customStrategy.needsRehash(PASSWORD, defaultHash),
                "Changed parameters should require rehash");
    }

    @Test(dataProvider = "defaultFactory", expectedExceptions = InvalidHashException.class,
            expectedExceptionsMessageRegExp = "Invalid hash format")
    public void shortHash(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = "$one$two$three";
        strategy.verify(PASSWORD, hash);
    }

    @Test(dataProvider = "defaultFactory", expectedExceptions = InvalidHashException.class,
            expectedExceptionsMessageRegExp = "Invalid hash format")
    public void longHash(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = "$one$two$three$four$five";
        strategy.verify(PASSWORD, hash);
    }

    @Test(dataProvider = "defaultFactory", expectedExceptions = InvalidHashException.class,
            expectedExceptionsMessageRegExp = "Invalid hash identifier")
    public void invalidIdentifier(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = "$INVALIDID$iterations=10000$asdf$asdfasdf";
        strategy.verify(PASSWORD, hash);
    }

    @Test(dataProvider = "defaultFactory", expectedExceptions = InvalidHashException.class,
            expectedExceptionsMessageRegExp = "Invalid hash parameter format")
    public void invalidParameterFormat(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = "$" + id + "$100000$asdf$asdfasdf";
        strategy.verify(PASSWORD, hash);
    }

    @Test(dataProvider = "defaultFactory", expectedExceptions = InvalidHashException.class,
            expectedExceptionsMessageRegExp = "Invalid hash parameter name")
    public void invalidParameterName(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = "$" + id + "$memory=10000$asdf$asdfasdf";
        strategy.verify(PASSWORD, hash);
    }

    @Test(dataProvider = "defaultFactory", expectedExceptions = InvalidHashException.class,
            expectedExceptionsMessageRegExp = "Non-numeric iteration count")
    public void nonNumeric(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = "$" + id + "$iterations=abcdefg$asdf$asdfasdf";
        strategy.verify(PASSWORD, hash);
    }

}
