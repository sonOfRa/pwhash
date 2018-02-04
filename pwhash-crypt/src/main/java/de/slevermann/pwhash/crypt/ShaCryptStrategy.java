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
package de.slevermann.pwhash.crypt;

import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;

/**
 * Base class for password hashing with SHA-{256,512}crypt
 *
 * @author Simon Levermann
 */
public abstract class ShaCryptStrategy implements HashStrategy {

    @Override
    public String hash(String password) {
        return null;
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {
        return false;
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        return false;
    }
}
