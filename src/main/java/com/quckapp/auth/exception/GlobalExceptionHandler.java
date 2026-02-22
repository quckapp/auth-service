package com.quckapp.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for REST controllers
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<Map<String, Object>> handleValidationException(ValidationException ex) {
        log.warn("Validation error: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", ex.getMessage());
        response.put("code", ex.getCode());
        if (ex.getField() != null) {
            response.put("field", ex.getField());
        }

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.warn("Bad request: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        String message = ex.getMostSpecificCause().getMessage();
        log.warn("Data integrity violation: {}", message);

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);

        // Parse the constraint violation to provide user-friendly message
        String lowerMessage = message != null ? message.toLowerCase() : "";
        if (lowerMessage.contains("username")) {
            response.put("message", "Username already exists");
            response.put("field", "username");
            response.put("code", "USERNAME_EXISTS");
        } else if (lowerMessage.contains("email")) {
            response.put("message", "Email already exists");
            response.put("field", "email");
            response.put("code", "EMAIL_EXISTS");
        } else if (lowerMessage.contains("phone")) {
            response.put("message", "Phone number already exists");
            response.put("field", "phoneNumber");
            response.put("code", "PHONE_EXISTS");
        } else {
            response.put("message", "A record with this value already exists");
            response.put("code", "DUPLICATE_ENTRY");
        }

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        // Check for common validation patterns in the message
        String message = ex.getMessage();
        if (message != null) {
            String lowerMessage = message.toLowerCase();

            // Handle "already exists" errors as conflicts
            if (lowerMessage.contains("already exists") ||
                lowerMessage.contains("already registered") ||
                lowerMessage.contains("already taken")) {

                log.warn("Conflict error: {}", message);

                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", message);
                response.put("code", "ALREADY_EXISTS");

                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
            }

            // Handle "not found" errors
            if (lowerMessage.contains("not found")) {
                log.warn("Not found: {}", message);

                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", message);

                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
        }

        // Log unexpected errors
        log.error("Unexpected error: {}", message, ex);

        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", message != null ? message : "An unexpected error occurred");

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
