package de.slevermann.pwhash.examples;

import de.slevermann.pwhash.HashStrategy;
import de.slevermann.pwhash.InvalidHashException;
import de.slevermann.pwhash.argon2.Argon2Strategy;
import de.slevermann.pwhash.argon2.Argon2idStrategy;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

/**
 * This class serves as an example for basic usage of the argon2 strategy, and proper use of
 * the {@link HashStrategy#needsRehash(String, String)} functionality, which is one of the core features of the
 * library.
 */
public class Argon2Example {
    private static final int CUSTOM_MEMORY_COST = Argon2Strategy.DEFAULT_MEMORY_COST * 2;
    private static final int CUSTOM_PARALLELISM = Argon2Strategy.DEFAULT_PARALLELISM * 2;
    private static final int CUSTOM_TIME_COST = Argon2Strategy.DEFAULT_TIME_COST * 2;

    private static final Jdbi jdbi = Jdbi.create("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1");

    /*
     * Argon2id with default parameters
     */
    private static HashStrategy strategy = Argon2Strategy.getDefault();

    public static void main(String[] args) {
        jdbi.installPlugin(new SqlObjectPlugin());
        jdbi.useExtension(UserDao.class, UserDao::createTable);
        System.out.println("Using default argon2 instance");
        String userName = "sonOfRa";
        String password = "test1234";
        System.out.println("Creating user " + userName + " with password " + password);

        String hash = strategy.hash(password);

        User u = new User();
        u.setName(userName);
        u.setPasswordHash(hash);

        System.out.println("Generated user: " + u);

        jdbi.useExtension(UserDao.class, dao -> dao.createUser(u));

        System.out.println("Switching to upgraded argon2 instance");
        strategy = new Argon2idStrategy(CUSTOM_MEMORY_COST, CUSTOM_PARALLELISM, CUSTOM_TIME_COST,
                Argon2Strategy.DEFAULT_SALT_LENGTH, Argon2Strategy.DEFAULT_HASH_LENGTH);

        User fromDB = jdbi.withExtension(UserDao.class, dao -> dao.findUser(userName));
        System.out.println("User fetched from DB: " + fromDB);

        System.out.println("Attempting to authenticate with password: " +
                (authenticateUser(u.getName(), password) ? "SUCCESS" : "FAILURE"));

        System.out.println("--------------------");
        System.out.println("Creating new additional user with upgraded argon2 instance");

        String newUserName = "newguy";
        String newPassword = "insecure";

        String newHash = strategy.hash(newPassword);

        User newUser = new User();
        newUser.setPasswordHash(newHash);
        newUser.setName(newUserName);

        System.out.println("Generated user: " + newUser);
        jdbi.useExtension(UserDao.class, dao -> dao.createUser(newUser));

        fromDB = jdbi.withExtension(UserDao.class, dao -> dao.findUser(newUserName));
        System.out.println("User fetched from DB: " + fromDB);

        System.out.println("Attempting to authenticate with password: " +
                (authenticateUser(newUser.getName(), newPassword) ? "SUCCESS" : "FAILURE"));

        System.out.println("Attempting to authenticate with wrong password: " +
                (authenticateUser(newUser.getName(), "incorrect") ? "SUCCESS" : "FAILURE"));
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
