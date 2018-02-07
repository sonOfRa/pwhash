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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Base class for password hashing with SHA-{256,512}crypt
 *
 * @author Simon Levermann
 * @see <a href="https://www.akkadia.org/drepper/SHA-crypt.txt">SHA-Crypt informal specification</a>
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
    private int blockSize;
    private int id;

    /**
     * Create a new shacrypt instance given rounds and a hash algorithm
     *
     * @param algorithm  the hash algorithm to use (can be sha256 or sha512)
     * @param rounds     the number of rounds to use for hashing, should be between 1000 and 999,999,999. Incorrect values are
     *                   automatically corrected as per the specification
     * @param saltLength length of the salt to use.
     * @param blockSize  the size of blocks to use for updating internal chunks. Should be equal to the output size of the used algorithm
     * @param id         identifier to use in the hash string
     */
    protected ShaCryptStrategy(String algorithm, int rounds, int saltLength, int blockSize, int id) {
        this.algorithm = algorithm;
        this.rounds = Math.min(Math.max(rounds, MIN_ROUNDS), MAX_ROUNDS);
        this.saltLength = Math.min(saltLength, MAX_SALT_LENGTH);
        this.secureRandom = new SecureRandom();
        this.blockSize = blockSize;
        this.id = id;
    }

    @Override
    public String hash(String password) {
        String salt = genSalt();
        byte[] hash = computeHash(password, salt, rounds);

        String hashString = B64Util.encode(hash);

        return "$" + id + "$rounds=" + rounds + "$" + salt + "$" + hashString;
    }

    /**
     * Hash the given password without embedding the amount of rounds into the hash.
     * <p>
     * This version always uses the default round count of 5000
     *
     * @param password the plaintext password to hash
     * @return a hashed password String containing all information necessary to verify it again later
     */
    protected String hashOld(String password) {
        String salt = genSalt();
        byte[] hash = computeHash(password, salt, DEFAULT_ROUNDS);

        String hashString = B64Util.encode(hash);

        return "$" + id + "$" + salt + "$" + hashString;
    }

    private byte[] computeHash(String password, String salt, int iterations) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes = Arrays.copyOf(salt.getBytes(StandardCharsets.UTF_8), 16);
        try {
            // 1.  start digest A
            MessageDigest a = MessageDigest.getInstance(algorithm);

            // 2.  the password string is added to digest A
            a.update(passwordBytes);

            // 3.  the salt string is added to digest A.
            a.update(saltBytes);

            // 4.  start digest B
            MessageDigest b = MessageDigest.getInstance(algorithm);

            // 5.  add the password to digest B
            b.update(passwordBytes);

            // 6.  add the salt string to digest B
            b.update(saltBytes);

            // 7.  add the password again to digest B
            b.update(passwordBytes);

            // 8.  finish digest B
            byte[] bResult = b.digest();

            /*
             * 9.  For each block of 32 or 64 bytes in the password string (excluding
             * the terminating NUL in the C representation), add digest B to digest A
             */
            int pwLength;
            for (pwLength = passwordBytes.length; pwLength > blockSize; pwLength -= blockSize) {
                a.update(bResult);
            }

            /*
             * 10. For the remaining N bytes of the password string add the first
             * N bytes of digest B to digest A
             */
            a.update(bResult, 0, pwLength);

            /*
             * 11. For each bit of the binary representation of the length of the
             * password string up to and including the highest 1-digit, starting
             * from to lowest bit position (numeric value 1):
             */
            for (pwLength = passwordBytes.length; pwLength > 0; pwLength >>>= 1) {
                if (pwLength % 2 == 1) {
                    // a) for a 1-digit add digest B to digest A
                    a.update(bResult);
                } else {
                    // b) for a 0-digit add the password string
                    a.update(passwordBytes);
                }
            }

            // 12. finish digest A
            byte[] aResult = a.digest();

            // 13. start digest DP
            MessageDigest dp = MessageDigest.getInstance(algorithm);

            /*
             * 14. for every byte in the password (excluding the terminating NUL byte
             * in the C representation of the string) add the password to digest DP
             */
            for (int i = 0; i < passwordBytes.length; ++i) {
                dp.update(passwordBytes);
            }

            // 15. finish digest DP
            byte[] dpResult = dp.digest();

            // 16. produce byte sequence P of the same length as the password where
            byte[] p = new byte[passwordBytes.length];

            int offset;
            for (pwLength = passwordBytes.length, offset = 0; pwLength >= blockSize; pwLength -= blockSize, offset += blockSize) {
                /*
                 * a) for each block of 32 or 64 bytes of length of the password string
                 *    the entire digest DP is used
                 */
                System.arraycopy(dpResult, 0, p, offset, blockSize);
            }
            /*
             * b) for the remaining N (up to  31 or 63) bytes use the first N
             *    bytes of digest DP
             */
            System.arraycopy(dpResult, 0, p, offset, pwLength);

            // 17. start digest DS
            MessageDigest ds = MessageDigest.getInstance(algorithm);

            /*
             * 18. repeat the following 16+A[0] times, where A[0] represents the first
             *     byte in digest A interpreted as an 8-bit unsigned value
             */
            for (int i = 0; i < 16 + Byte.toUnsignedInt(aResult[0]); i++) {
                // add the salt to digest DS
                ds.update(saltBytes);
            }

            // 19. finish digest DS
            byte[] dsResult = ds.digest();

            // 20. produce byte sequence S of the same length as the salt string where
            byte[] s = new byte[saltBytes.length];
            int saltLength;
            for (saltLength = saltBytes.length, offset = 0; saltLength >= blockSize; saltLength -= blockSize, offset += blockSize) {
                /*
                 * a) for each block of 32 or 64 bytes of length of the salt string
                 *    the entire digest DS is used
                 */
                System.arraycopy(dsResult, 0, s, offset, blockSize);
            }
            /*
             * b) for the remaining N (up to  31 or 63) bytes use the first N
             *    bytes of digest DS
             */
            System.arraycopy(dsResult, 0, s, offset, saltLength);

            /*
             * 21. repeat a loop according to the number specified in the rounds=<N>
             *     specification in the salt (or the default value if none is
             *     present).  Each round is numbered, starting with 0 and up to N-1.
             *
             *     The loop uses a digest as input.  In the first round it is the
             *     digest produced in step 12.  In the latter steps it is the digest
             *     produced in step 21.h of the previous round.  The following text
             *     uses the notation "digest A/C" to describe this behavior.
             */
            byte[] acResult = Arrays.copyOf(aResult, aResult.length);

            // a) start digest C (instances are automatically reusable after calling .digest() in java)
            MessageDigest c = MessageDigest.getInstance(algorithm);
            for (int i = 0; i < iterations; i++) {
                if (i % 2 == 1) {
                    // b) for odd round numbers add the byte sequense P to digest C
                    c.update(p);
                } else {
                    // c) for even round numbers add digest A/C
                    c.update(acResult);
                }

                if (i % 3 != 0) {
                    // d) for all round numbers not divisible by 3 add the byte sequence S
                    c.update(s);
                }

                if (i % 7 != 0) {
                    // e) for all round numbers not divisible by 7 add the byte sequence P
                    c.update(p);
                }

                if (i % 2 == 1) {
                    // f) for odd round numbers add digest A/C
                    c.update(acResult);
                } else {
                    // g) for even round numbers add the byte sequence P
                    c.update(p);
                }

                // h) finish digest C
                acResult = c.digest();
            }
            // Shuffle output according to 22. e)
            return shuffle(acResult);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Missing implementation for " + algorithm, ex);
        }
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
        String[] chunks = hash.split("\\$");

        int chunkCount = chunks.length;
        if (chunkCount > 5 || chunkCount < 4) {
            throw new InvalidHashException("ShaCrypt hash must have 4 or 5 chunks");
        }

        int extractedId = Integer.parseInt(chunks[1]);

        if (extractedId != id) {
            throw new InvalidHashException("Invalid shacrypt ID");
        }

        int currentChunk = 2;

        int rounds = DEFAULT_ROUNDS;
        if (chunkCount == 5) {
            String[] roundChunks = chunks[currentChunk].split("=");
            if (!roundChunks[0].equals("rounds")) {
                throw new InvalidHashException("Invalid option");
            }
            rounds = Integer.parseInt(chunks[currentChunk].split("=")[1]);
            rounds = Math.min(Math.max(rounds, MIN_ROUNDS), MAX_ROUNDS);
            currentChunk++;
        }

        String salt = chunks[currentChunk];
        currentChunk++;
        String extractedHash = chunks[currentChunk];

        int hashLength = extractedHash.length();

        if ((hashLength * 3) / 4 != blockSize) {
            throw new InvalidHashException("Invalid hash length");
        }

        byte[] extractedHashBytes = B64Util.decode(extractedHash);

        byte[] passwordHashBytes = computeHash(password, salt, rounds);
        System.out.println(extractedHashBytes.length + " " + passwordHashBytes.length);
        return MessageDigest.isEqual(extractedHashBytes, passwordHashBytes);
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        try {
            if (!verify(password, hash)) {
                return false;
            }
        } catch (InvalidHashException ex) {
            return false;
        }

        String[] chunks = hash.split("\\$");

        int currentChunk = 2;
        int extractedRounds = DEFAULT_ROUNDS;
        if (chunks.length == 5) {
            extractedRounds = Integer.parseInt(chunks[currentChunk].split("=")[1]);
            currentChunk++;
        }

        if (extractedRounds != rounds) {
            return true;
        }

        String salt = chunks[currentChunk];

        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);

        return saltBytes.length == saltLength;
    }

    /**
     * Shuffle bytes around before encoding according to the crypt rules.
     * <p>
     * The rules are defined in section 22. e) of the "standard"
     *
     * @param data unshuffled data
     * @return shuffled data
     */
    protected abstract byte[] shuffle(byte[] data);
}
