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

/**
 * Strategy implementation for sha512crypt
 * <p>
 * This implementation does not store the rounds parameter in the hash, and instead always uses the default round value
 * of 5000
 *
 * @author Simon Levermann
 */
public class Sha512OldCryptStrategy extends Sha512CryptStrategy {
    /**
     * Create a new shacrypt instance with the given rounds and salt length
     *
     * @param saltLength length of the salt to use.
     */
    public Sha512OldCryptStrategy(int saltLength) {
        super(DEFAULT_ROUNDS, saltLength);
    }

    @Override
    public String hash(String password) {
        return hashOld(password);
    }
}
