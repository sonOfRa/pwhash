package de.slevermann.pwhash;

/**
 * A strategy to migrate from one strategy to another.
 * <p>
 * It is not necessary to use this when upgrading parameters inside a single strategy.
 * However, this class is useful when migrating from one hash algorithm to another, which may have
 * different formats etc.
 */
public class MigrationStrategy implements HashStrategy {

    private HashStrategy oldStrategy;

    private HashStrategy newStrategy;

    public MigrationStrategy(HashStrategy oldStrategy, HashStrategy newStrategy) {
        this.oldStrategy = oldStrategy;
        this.newStrategy = newStrategy;
    }

    @Override
    public String hash(String password) {
        return newStrategy.hash(password);
    }

    @Override
    public boolean verify(String password, String hash) {
        boolean result;
        try {
            result = oldStrategy.verify(password, hash);
        } catch (InvalidHashException e) {
            result = false;
        }

        if (result) {
            return true;
        }

        try {
            return newStrategy.verify(password, hash);
        } catch (InvalidHashException e) {
            return false;
        }
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        boolean result;
        /*
         * If the password matches the old style hash, we need to rehash
         */
        try {
            result = oldStrategy.verify(password, hash);
        } catch (InvalidHashException ex) {
            result = false;
        }

        if (result) {
            return true;
        }

        /*
         * If the password matches neither the old nor the new hash style,
         * we don't want to rehash
         */
        try {
            if (!newStrategy.verify(password, hash)) {
                return false;
            }
        } catch (InvalidHashException ex) {
            return false;
        }

        /*
         * Password successfully verified, check if we need to update parameters inside
         * the new style
         */
        return newStrategy.needsRehash(password, hash);
    }
}
