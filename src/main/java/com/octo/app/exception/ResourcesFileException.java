package com.octo.app.exception;

/**
 * Resources file exception object.
 * This exception is used in ResourcesFile object.
 */
public class ResourcesFileException extends RuntimeException {

    /**
     * Create a resources file exception with a message.
     *
     * @param message the exception message.
     */
    public ResourcesFileException(String message) {
        super(message);
    }
}
