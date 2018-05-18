package com.octo.app.exception;

/**
 * Encrypt file exception.
 * This exception is used in EcryptFile object.
 */
public class KeyException extends RuntimeException {

    /**
     * Create an encrypt file exception with a message.
     *
     * @param message the exception message.
     */
    public KeyException(String message) {
        super(message);
    }

    /**
     * Create an encrypte file exception with a message and a cause.
     *
     * @param message the exception message.
     * @param cause   the exception cause.
     */
    public KeyException(String message, Throwable cause) {
        super(message, cause);
    }

}
