package de.slevermann.pwhash.examples.common;

import lombok.Data;

@Data
public class User {
    private String name;
    private String passwordHash;
}
