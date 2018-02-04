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

import org.mindrot.jbcrypt.BCrypt;

/**
 * A strategy implementation using bcrypt
 * <p>
 * Uses a work factor of 10 by default.
 *
 * @author Simon Levermann
 */
public class BCryptStrategy implements HashStrategy {

    public static final int DEFAULT_WORK_FACTOR = 10;

    private int workFactor;

    /**
     * Construct a default bcrypt instance
     */
    public BCryptStrategy() {
        this(DEFAULT_WORK_FACTOR);
    }

    /**
     * Construct a bcrypt instance with a custom work factor
     *
     * @param workFactor the work factor to use
     */
    private BCryptStrategy(int workFactor) {
        this.workFactor = workFactor;
    }

    @Override
    public String hash(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(workFactor));
    }

    @Override
    public boolean verify(String password, String hash) throws InvalidHashException {

        try {
            return BCrypt.checkpw(password, hash);
        } catch (IllegalArgumentException ex) {
            throw new InvalidHashException(ex);
        }
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        /*
         * If the password fails to verify against the given hash, it might not be a valid hash. Abort here.
         */
        try {
            if (!verify(password, hash)) {
                return false;
            }
        } catch (InvalidHashException ex) {
            return false;
        }

        int extractedWorkFactor = Integer.parseInt(hash.split("\\$")[2]);

        return extractedWorkFactor != this.workFactor;
    }


    /**
     * Get a custom bcrypt instance
     *
     * @param workFactor the work factor, must be 1 &lt;= workFactor &lt; 30
     * @return the customized bcrypt instance
     * @throws InvalidHashException if the work factor is invalid
     */
    public static BCryptStrategy getInstance(int workFactor) throws InvalidHashException {
        if (workFactor < 1 || workFactor > 30) {
            throw new InvalidHashException("Work factor must be between 1 and 30");
        }
        return new BCryptStrategy(workFactor);
    }
}
