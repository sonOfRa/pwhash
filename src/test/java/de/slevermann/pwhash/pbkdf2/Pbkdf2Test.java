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

public class Pbkdf2Test {
    private static final String PASSWORD = "The Magic Words are Squeamish Ossifrage";

    @Test(dataProvider = "defaultFactory", dataProviderClass = Pbkdf2Provider.class)
    public void defaultType(Pbkdf2Strategy defaultStrategy, String id) throws InvalidHashException {
        String hash = defaultStrategy.hash(PASSWORD);

        Assert.assertTrue(defaultStrategy.verify(PASSWORD, hash), "Password should match");

        String[] chunks = hash.split("\\$");
        Assert.assertEquals(chunks[1], id, "Identifer should be " + id);

        Assert.assertEquals(Integer.parseInt(chunks[2].split("=")[1]), Pbkdf2Strategy.DEFAULT_ITERATIONS,
                "Iteration count should be default");
    }

    @Test(dataProvider = "defaultFactory", dataProviderClass = Pbkdf2Provider.class)
    public void wrongPassword(Pbkdf2Strategy strategy, String id) throws InvalidHashException {
        String hash = strategy.hash(PASSWORD);
        Assert.assertFalse(strategy.verify("WRONG", hash));
    }

    @Test(dataProvider = "customFactory", dataProviderClass = Pbkdf2Provider.class)
    public void customParameters(Pbkdf2Strategy strategy, int iterations) {
        String hash = strategy.hash(PASSWORD);

        Assert.assertEquals(Integer.parseInt(hash.split("\\$")[2].split("=")[1]), iterations,
                "Iteration count should be custom");
    }

    @Test(dataProvider = "customFactory", dataProviderClass = Pbkdf2Provider.class)
    public void customParametersWrongPassword(Pbkdf2Strategy strategy, int iterations) throws InvalidHashException {
        String hash = strategy.hash(PASSWORD);
        Assert.assertFalse(strategy.verify("WRONG", hash));
    }

    @Test(dataProviderClass = Pbkdf2Provider.class, dataProvider = "defaultFactory")
    public void noRehash(Pbkdf2Strategy strategy, String id) {
        String hash = strategy.hash(PASSWORD);

        Assert.assertFalse(strategy.needsRehash(PASSWORD, hash), "Unchanged parameters should not require rehash");
    }

    @Test(dataProviderClass = Pbkdf2Provider.class, dataProvider = "defaultFactory")
    public void noRehashInvalid(Pbkdf2Strategy strategy, String id) {
        Assert.assertFalse(strategy.needsRehash(PASSWORD, "INVALID"),
                "Invalid hash should not require rehash");
    }
}
