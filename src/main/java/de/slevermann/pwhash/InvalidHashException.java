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

/**
 * Exception to be thrown when an invalid hash is given
 *
 * @author Simon Levermann
 */
public class InvalidHashException extends Exception {

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
