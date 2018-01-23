package de.slevermann.pwhash;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HashStrategy interface to unify different hashing strategies. Any options passed to the hashing functions
 * should be implemented as constructor parameters or constants. Constructor parameters are recommended, because it allows
 * easier migration to higher work factors or changing of other options like output length etc.
 *
 * @author Simon Levermann
 */
public interface HashStrategy {

    /**
     * Hash the given password
     *
     * @param password the plaintext password to hash
     * @return a hashed password String containing all information necessary to verify it again later
     */
    String hash(String password);

    /**
     * Verify the given password against a hashed password
     *
     * @param password the password to verify
     * @param hash     a hash String as returned by {@link #hash(String)}
     * @return true if the password matches the hash, false otherwise
     */
    boolean verify(String password, String hash);

    /**
     * Check whether a stored hash needs to be rehashed to comply with the options set by the implementation
     * <p>
     * This function should be called after verifying a given password. If the password matches, we can then check whether the
     * options and parameters in the stored hash are the same as the options given by the implementation.
     *
     * @param hash the hash to check
     * @return true if the password needs to be rehashed (options do NOT match), false otherwise
     */
    boolean needsRehash(String hash);
}
