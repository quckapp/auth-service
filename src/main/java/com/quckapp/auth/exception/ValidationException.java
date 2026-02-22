package com.quckapp.auth.exception;

/**
 * Exception for validation errors (duplicate email, username, etc.)
 */
public class ValidationException extends RuntimeException {
    private final String field;
    private final String code;

    public ValidationException(String message) {
        super(message);
        this.field = null;
        this.code = "VALIDATION_ERROR";
    }

    public ValidationException(String field, String message) {
        super(message);
        this.field = field;
        this.code = "VALIDATION_ERROR";
    }

    public ValidationException(String field, String message, String code) {
        super(message);
        this.field = field;
        this.code = code;
    }

    public String getField() {
        return field;
    }

    public String getCode() {
        return code;
    }
}
