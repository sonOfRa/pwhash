package de.slevermann.pwhash.examples;

import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.customizer.BindBean;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

public interface UserDao {
    @SqlUpdate("CREATE TABLE user (name VARCHAR PRIMARY KEY, passwordHash VARCHAR)")
    void createTable();

    @SqlUpdate("INSERT INTO user(name, passwordHash) VALUES (:name, :passwordHash)")
    void createUser(@BindBean User user);

    @SqlQuery("SELECT * FROM user WHERE name LIKE :name LIMIT 1")
    @RegisterBeanMapper(User.class)
    User findUser(@Bind("name") String name);

    @SqlUpdate("UPDATE user SET passwordHash = :passwordHash WHERE name LIKE :name")
    void updateHash(@Bind("name") String name, @Bind("passwordHash") String passwordHash);
}
