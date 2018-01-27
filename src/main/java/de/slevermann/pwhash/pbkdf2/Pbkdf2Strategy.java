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

import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * A strategy implementation using PBKDF2 for password hashing.
 * <p>
 * By default, PBKDF2WithHMACSha512 is used.
 *
 * @author Simon Levermann
 */
public abstract class Pbkdf2Strategy implements HashStrategy {

    public static final int DEFAULT_ITERATIONS = 20000;

    private SecretKeyFactory keyFactory;
    private String id;
    private SecureRandom secureRandom;
    private int saltLength;
    private int dkLength;
    private int iterations;

    public Pbkdf2Strategy(int saltLength, int dkLength, int iterations, String id) {
        this.saltLength = saltLength;
        this.dkLength = dkLength;
        this.iterations = iterations;
        this.secureRandom = new SecureRandom();
        try {
            this.keyFactory = SecretKeyFactory.getInstance(id);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + id + " implementation", e);
        }
        this.id = id.toLowerCase();
    }

    @Override
    public String hash(String password) {
        String output = "$" + this.id + "$" + "iterations=" + this.iterations + "$";
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);

        Base64.Encoder b64Encoder = Base64.getEncoder().withoutPadding();

        output += b64Encoder.encodeToString(salt) + "$";

        byte[] hash = computeHash(password, salt, this.iterations);

        output += b64Encoder.encodeToString(hash);
        return output;
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {
        String[] chunks = hash.split("\\$");

        if (!chunks[1].equals(id)) {
            throw new InvalidHashException("Invalid hash identifier");
        }

        int extractedIterations = Integer.parseInt(chunks[2].split("=")[1]);

        Base64.Decoder b64Decoder = Base64.getDecoder();
        byte[] salt = b64Decoder.decode(chunks[3]);
        byte[] extractedHash = b64Decoder.decode(chunks[4]);

        byte[] computedHash = computeHash(password, salt, extractedIterations);

        return MessageDigest.isEqual(extractedHash, computedHash);
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        boolean result;
        try {
            result = verify(password, hash);
        } catch (InvalidHashException ex) {
            return false;
        }

        if (result) {
            return true;
        }

        int extractedIterations = Integer.parseInt(hash.split("\\$")[2].split("=")[1]);
        return extractedIterations != this.iterations;
    }

    private byte[] computeHash(String password, byte[] salt, int iterations) {
        char[] passwordArray = password.toCharArray();
        PBEKeySpec keySpec = new PBEKeySpec(passwordArray, salt, iterations, dkLength * 8);
        try {
            return keyFactory.generateSecret(keySpec).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
