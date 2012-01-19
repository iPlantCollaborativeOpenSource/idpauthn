package org.iplantc.idpauthn;

import javax.security.auth.login.LoginException;

/**
 * Provides a general way to validate a username and password.
 *
 * @author Dennis Roberts
 */
public interface PasswordValidator {

    /**
     * Validates a username and password.
     *
     * @param username the username to validate.
     * @param encryptedPassword the encrypted version of the password to validate.
     * @throws LoginException if the username and password are invalid or can't be validated.
     */
    public void validatePassword(String username, String encryptedPassword) throws LoginException;
}
