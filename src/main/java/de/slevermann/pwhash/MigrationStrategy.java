package de.slevermann.pwhash;

/**
 * A strategy to migrate from one strategy to another.
 * <p>
 * It is not necessary to use this when upgrading parameters inside a single strategy.
 * However, this class is useful when migrating from one hash algorithm to another, which may have
 * different formats etc.
 *
 * @param <F> the strategy to migrate from
 * @param <T> the strategy to migrate to
 */
public class MigrationStrategy<F extends HashStrategy, T extends HashStrategy> implements HashStrategy {

    private F oldStrategy;

    private T newStrategy;

    public MigrationStrategy(F oldStrategy, T newStrategy) {
        this.oldStrategy = oldStrategy;
        this.newStrategy = newStrategy;
    }

    @Override
    public String hash(String password) {
        return newStrategy.hash(password);
    }

    @Override
    public boolean verify(String password, String hash) {
        return oldStrategy.verify(password, hash) || newStrategy.verify(password, hash);
    }

    @Override
    public boolean needsRehash(String password, String hash) {
        /*
         * If the password matches the old style hash, we need to rehash
         */
        if (oldStrategy.verify(password, hash)) {
            return true;
        }

        /*
         * If the password matches neither the old nor the new hash style,
         * we don't want to rehash
         */
        if (!newStrategy.verify(password, hash)) {
            throw new IllegalArgumentException("Cannot verify hash");
        }

        /*
         * Password successfully verified, check if we need to update parameters inside
         * the new style
         */
        return newStrategy.needsRehash(password, hash);
    }
}
