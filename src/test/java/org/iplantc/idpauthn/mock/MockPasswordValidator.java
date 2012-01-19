package org.iplantc.idpauthn.mock;

import javax.security.auth.login.LoginException;

import org.iplantc.idpauthn.PasswordValidator;

/**
 * A mock password validator for use during testing.
 *
 * @author Dennis Roberts
 */
public class MockPasswordValidator implements PasswordValidator {

    /**
     * True if the username and password should be accepted.
     */
    private boolean acceptPassword = true;
    
    /**
     * True if validatePassword() has been called.
     */
    private boolean validatePasswordCalled = false;
    
    /**
     * The username that was passed to us.
     */
    private String username = null;
    
    /**
     * The password that was passed to us.
     */
    private String encryptedPassword = null;

    /**
     * The setter for the acceptPassword property.
     *
     * @param acceptPassword true if the username and password should be accepted.
     */
    public void setAcceptPassword(boolean acceptPassword) {
        this.acceptPassword = acceptPassword;
    }
    
    /**
     * The getter for the validatePasswordCalled property.
     * 
     * @return true if validatePassword() has been called.
     */
    public boolean getValidatePasswordCalled() {
        return validatePasswordCalled;
    }

    /**
     * The getter for the username property.
     *
     * @return the username.
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * The getter for the encryptedPassword property.
     * 
     * @return the encrypted version of the password.
     */
    public String getEncryptedPassword() {
        return encryptedPassword;
    }
    
    /**
     * Validates a username and password.
     * 
     * @param username the username to validate.
     * @param encryptedPassword the encrypted version of the password to validate.
     * @throws LoginException if the username and password are invalid or can't be validated.
     */
    public void validatePassword(String username, String encryptedPassword) throws LoginException {
        validatePasswordCalled = true;
        this.username = username;
        this.encryptedPassword = encryptedPassword;
        if (!acceptPassword) {
            throw new LoginException("Uh, I'm not supposed to let you in");
        }
    }
}
