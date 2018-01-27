package de.slevermann.pwhash;

import org.omg.CORBA.DynAnyPackage.Invalid;

/**
 * Exception to be thrown when an invalid hash is given
 */
public class InvalidHashException extends Exception {

    /**
     * Construct an exception with no further information
     */
    public InvalidHashException() {
    }

    /**
     * Construct an exception with given cause and message
     *
     * @param message the error message
     */
    public InvalidHashException(String message) {
        super(message);
    }

    /**
     * Construct an exception with the given cause
     *
     * @param cause the cause of the exception
     */
    public InvalidHashException(Throwable cause) {
        super(cause);
    }

    /**
     * Construct an exception with given cause and message
     *
     * @param message the error message
     * @param cause   the cause of the exception
     */
    public InvalidHashException(String message, Throwable cause) {
        super(message, cause);
    }

}
