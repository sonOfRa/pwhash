package de.slevermann.pwhash;

/**
 * Exception to be thrown when an invalid hash is given
 */
public class InvalidHashException extends Exception {

    /**
     * Construct an exception with the given cause
     *
     * @param cause the cause of the exception
     */
    public InvalidHashException(Throwable cause) {
        super(cause);
    }
}
