package org.iplantc.idpauthn.mock;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * A mock callback handler for testing.
 *
 * @author Dennis Roberts
 */
public class MockCallbackHandler implements CallbackHandler {

    /**
     * The username to use for authentication.
     */
    private String username = "nameofsomeuser";
    
    /**
     * The password to use for authentication.
     */
    private String password = "passwordofsomeuser";
    
    /**
     * True if we should throw an UnsupportedCallbackException whenever handle() is called.
     */
    private boolean rejectCallbacks = false;
    
    /**
     * True if we should throw an IOException whenever handle() is called.
     */
    private boolean throwIoException = false;
    
    /**
     * True if handle() has been called.
     */
    private boolean handleCalled = false;

    /**
     * The setter for the username property.
     *
     * @param username the new username.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * The setter for the password property.
     *
     * @param password the new password.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * The setter for the rejectCallbacks property.
     *
     * @param rejectCallbacks true if we should reject all callbacks.
     */
    public void setRejectCallbacks(boolean rejectCallbacks) {
        this.rejectCallbacks = rejectCallbacks;
    }

    /**
     * The setter for the throwIoException property.
     *
     * @param throwIoException true if we should throw an IOException when handle() is called.
     */
    public void setThrowIoException(boolean throwIoException) {
        this.throwIoException = throwIoException;
    }
    
    /**
     * The getter for the handleCalled property.
     *
     * @return true if handle() has been called.
     */
    public boolean getHandleCalled() {
        return handleCalled;
    }

    /**
     * Handles a list of callbacks.
     *
     * @param callbacks the array of callbacks.
     * @throws IOException if we're configured to throw one.
     * @throws UnsupportedCallbackException if we're configured to throw one.
     */
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        handleCalled = true;
        if (rejectCallbacks) {
            throw new UnsupportedCallbackException(callbacks[0], "Not gonna d'it!");
        }
        if (throwIoException) {
            throw new IOException("Huh?");
        }
        for (int i = 0; i < callbacks.length; i++) {
            handleCallback(callbacks[i]);
        }
    }

    /**
     * Handles a single callback.
     *
     * @param callback the callback to use.
     * @throws UnsupportedCallbackException if we don't know how to handle the callback.
     */
    public void handleCallback(Callback callback) throws UnsupportedCallbackException {
        if (callback instanceof PasswordCallback) {
            ((PasswordCallback) callback).setPassword(password.toCharArray());
        }
        else if (callback instanceof NameCallback) {
            ((NameCallback) callback).setName(username);
        }
        else {
            throw new UnsupportedCallbackException(callback, "What is this 'callback' of which you speak?");
        }
    }
}
