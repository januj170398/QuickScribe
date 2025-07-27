package com.anuj.QuickScribe.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Value;

import java.util.regex.Pattern;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    @Value("${app.security.password-strength:8}")
    private int minLength;

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile(".*[a-z].*");
    private static final Pattern DIGIT_PATTERN = Pattern.compile(".*\\d.*");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*");

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        // Initialization if needed
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            return false;
        }

        // Check minimum length
        if (password.length() < minLength) {
            addViolation(context, "Password must be at least " + minLength + " characters long");
            return false;
        }

        // Check for uppercase letter
        if (!UPPERCASE_PATTERN.matcher(password).matches()) {
            addViolation(context, "Password must contain at least one uppercase letter");
            return false;
        }

        // Check for lowercase letter
        if (!LOWERCASE_PATTERN.matcher(password).matches()) {
            addViolation(context, "Password must contain at least one lowercase letter");
            return false;
        }

        // Check for digit
        if (!DIGIT_PATTERN.matcher(password).matches()) {
            addViolation(context, "Password must contain at least one digit");
            return false;
        }

        // Check for special character
        if (!SPECIAL_CHAR_PATTERN.matcher(password).matches()) {
            addViolation(context, "Password must contain at least one special character");
            return false;
        }

        return true;
    }

    private void addViolation(ConstraintValidatorContext context, String message) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    }
}
