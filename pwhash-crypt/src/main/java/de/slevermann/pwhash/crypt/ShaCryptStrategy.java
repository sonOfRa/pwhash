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

import java.security.SecureRandom;

/**
 * Base class for password hashing with SHA-{256,512}crypt
 *
 * @author Simon Levermann
 */
public abstract class ShaCryptStrategy implements HashStrategy {

    public static final int DEFAULT_ROUNDS = 5000;
    private static final int MIN_ROUNDS = 1000;
    private static final int MAX_ROUNDS = 999999999;

    private static final int MAX_SALT_LENGTH = 16;

    private String algorithm;
    private int rounds;
    private SecureRandom secureRandom;
    private int saltLength;

    /**
     * Create a new shacrypt instance given rounds and a hash algorithm
     *
     * @param algorithm the hash algorithm to use (can be sha256 or sha512)
     * @param rounds    the number of rounds to use for hashing
     */
    protected ShaCryptStrategy(String algorithm, int rounds, int saltLength) {
        this.algorithm = algorithm;
        this.rounds = Math.min(Math.max(rounds, MIN_ROUNDS), MAX_ROUNDS);
        this.saltLength = Math.min(saltLength, MAX_SALT_LENGTH);
        this.secureRandom = new SecureRandom();
    }

    @Override
    public String hash(String password) {
        return null;
    }

    /**
     * Hash the given password without embedding the amount of rounds into the hash.
     * <p>
     * This version always uses the default round count of 5000
     *
     * @param password the plaintext password to hash
     * @return a hashed password String containing all information necessary to verify it again later
     */
    public String hashOld(String password) {
        return null;
    }

    private byte[] computeHash(String password, byte[] salt) {
        return null;
    }

    private String genSalt() {
        StringBuilder sb = new StringBuilder(saltLength);
        for (int i = 0; i < saltLength; i++) {
            int index = secureRandom.nextInt(B64Util.B64_LOOKUP.length());
            sb.append(B64Util.B64_LOOKUP.charAt(index));
        }
        return sb.toString();
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {
        return false;
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        return false;
    }

    /**
     * Shuffle bytes around before encoding according to the crypt rules
     *
     * @param data unshuffled data
     * @return shuffled data
     */
    protected abstract byte[] shuffle(byte[] data);
}
