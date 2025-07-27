package com.anuj.QuickScribe.exception;

/**
 * Exception thrown when authentication fails or user authentication cannot be processed
 */
public class AuthenticationException extends RuntimeException {

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
