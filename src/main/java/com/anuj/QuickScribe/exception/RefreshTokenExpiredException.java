package com.anuj.QuickScribe.exception;

public class RefreshTokenExpiredException extends RuntimeException {

    public RefreshTokenExpiredException(String message) {
        super(message);
    }

    public RefreshTokenExpiredException() {
        super("Refresh token was expired. Please make a new signin request");
    }
}
