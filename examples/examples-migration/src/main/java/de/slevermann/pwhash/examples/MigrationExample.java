package de.slevermann.pwhash.examples;

import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;
import de.slevermann.pwhash.MigrationStrategy;
import de.slevermann.pwhash.argon2.Argon2Strategy;
import de.slevermann.pwhash.pbkdf2.Pbkdf2WithHmacSha512Strategy;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

/**
 * This class serves as an example for basic usage of the MigrationStrategy
 */
public class MigrationExample {
    private static final Jdbi jdbi = Jdbi.create("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1");

    /*
     * Migrate away from PBKDF2-SHA512
     */
    private static HashStrategy oldStrategy = new Pbkdf2WithHmacSha512Strategy();

    /*
     * Migrate to argon2id
     */
    private static HashStrategy newStrategy = Argon2Strategy.getDefault();

    /*
     * The actual migration strategy
     */
    private static HashStrategy strategy = new MigrationStrategy(oldStrategy, newStrategy);

    public static void main(String[] args) {
        jdbi.installPlugin(new SqlObjectPlugin());
        jdbi.useExtension(UserDao.class, UserDao::createTable);

        System.out.println("Starting out with old password hash");

        String userName = "sonOfRa";
        String password = "test1234";
        System.out.println("Creating user " + userName + " with password " + password);

        String hash = oldStrategy.hash(password);

        User user = new User();
        user.setName(userName);
        user.setPasswordHash(hash);

        System.out.println("Generated user: " + user);

        jdbi.useExtension(UserDao.class, dao -> dao.createUser(user));
        User fromDB = jdbi.withExtension(UserDao.class, dao -> dao.findUser(userName));
        System.out.println("User fetched from DB: " + fromDB);

        System.out.println("Trying to authenticate user with MigrationStrategy: " +
                (authenticateUser(userName, password) ? "SUCCESS" : "FAILURE"));

        fromDB = jdbi.withExtension(UserDao.class, dao -> dao.findUser(userName));
        System.out.println("User in database after authenticating: " + fromDB);
    }

    /*
     * Authenticate a user with the given password
     */
    private static boolean authenticateUser(String userName, String password) {
        User u = jdbi.withExtension(UserDao.class, dao -> dao.findUser(userName));

        /*
         * If we can't find the user, we obviously return false
         */
        if (u == null) {
            return false;
        }


        try {
            if (!strategy.verify(password, u.getPasswordHash())) {
                /*
                 * This means the password failed to verify
                 */
                return false;
            }
        } catch (InvalidHashException ex) {
            /*
             * This exception usually means a programming error, like picking the wrong strategy for the hash type
             */
            return false;
        }

        /*
         * If we get here, the user was authenticated successfully. Now we check for rehashing.
         * This part is important for compatibility. This allows you to switch out hashes later on.
         */
        if (strategy.needsRehash(password, u.getPasswordHash())) {
            System.out.println("Rehashing current password for user " + userName);
            String hash = strategy.hash(password);

            /*
             * Now that we've got the new hash, update it in the database
             */
            jdbi.useExtension(UserDao.class, dao -> dao.updateHash(u.getName(), hash));
        } else {
            System.out.println("Not rehashing, password is up-to-date");
        }

        // Authentication was successful, whether or not we need to rehash
        return true;
    }
}
