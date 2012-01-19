package org.iplantc.idpauthn;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.iplantc.securitytoolkit.PasswordEncrypter;

/**
 * A JAAS login module that authenticates a username and password against a database.
 * 
 * @author Dennis Roberts
 */
@SuppressWarnings("unused")
public class DatabaseLogin implements LoginModule {

    /**
     * The subject of the login request.
     */
    private Subject subject;

    /**
     * The callback handler used to obtain the username and password.
     */
    private CallbackHandler callbackHandler;

    /**
     * A map of state information that is shared among the various login modules.
     */
    private Map<String, ?> sharedState;

    /**
     * The configuration options used to initialize this login module.
     */
    private Map<String, ?> options;

    /**
     * The hash algorithm used to encrypt the password (defaults to "SHA-512").
     */
    private String hashAlgorithm = "SHA-512";

    /**
     * The character encoding to be used when encrypting the password (defaults to "UTF-8").
     */
    private String characterEncoding = "UTF-8";

    /**
     * The name of the database driver.
     */
    private String databaseDriverName = null;

    /**
     * The URL used to connect to the database.
     */
    private String databaseUrl = null;

    /**
     * The query used to search the database.
     */
    private String databaseQuery = null;

    /**
     * The password validator to use when validating the passwords. This defaults to an instance of
     * DatabasePasswordValidator, but may be changed for testing.
     */
    PasswordValidator passwordValidator = null;

    /**
     * The password encrypter to use when encrypting the passwords.
     */
    PasswordEncrypter passwordEncrypter = null;

    /**
     * True if the login attempt succeeds.
     */
    private boolean loginSucceeded = false;

    /**
     * True if the session has been committed.
     */
    private boolean commitSucceeded = false;

    /**
     * The username that is being validated.
     */
    private String username = null;

    /**
     * The password that is being validated.
     */
    private String password = null;

    /**
     * The identified principal information.
     */
    private Principal userPrincipal = null;

    /**
     * Returns the hash algorithm that is being used to encrypt the passwords.
     * 
     * @return the name of the hash algorithm.
     */
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Returns the character encoding that is being used while encrypting the passwords.
     * 
     * @return the name of the character encoding.
     */
    public String getCharacterEncoding() {
        return characterEncoding;
    }

    /**
     * The getter for the databaseDriverName property.
     * 
     * @return the database driver name.
     */
    public String getDatabaseDriverName() {
        return databaseDriverName;
    }

    /**
     * The getter for the databaseUrl property.
     * 
     * @return the URL used to connect to the database.
     */
    public String getDatabaseUrl() {
        return databaseUrl;
    }

    /**
     * The getter for the databaseQuery property.
     * 
     * @return the query used to validate the username and password.
     */
    public String getDatabaseQuery() {
        return databaseQuery;
    }

    /**
     * Allows the password validator to be changed for testing purposes.
     * 
     * @param passwordValidator the new password validator.
     */
    public void setPasswordValidatorForTesting(PasswordValidator passwordValidator) {
        this.passwordValidator = passwordValidator;
    }

    /**
     * Aborts the authentication process.
     * 
     * @return true if the authentication process was successfully aborted, false if it didn't need to be.
     * @throws LoingException if the authentication process couldn't be aborted.
     */
    public boolean abort() throws LoginException {
        boolean result = false;
        if (loginSucceeded) {
            cleanUpAfterLogin();
            result = true;
        }
        return result;
    }

    /**
     * Commits the authentication process.
     * 
     * @return true if the authentication was successfully committed.
     * @throws LoginException if the login was successful but the commit was not.
     */
    public boolean commit() throws LoginException {
        commitSucceeded = false;
        if (loginSucceeded) {
            addPrincipal();
            cleanUpAfterLogin();
            commitSucceeded = true;
        }
        return commitSucceeded;
    }

    /**
     * Cleans up state information after an authentication attempt has completed (either successfully or
     * unsuccessfully).
     */
    private void cleanUpAfterLogin() {
        username = null;
        password = null;
    }

    /**
     * Creates the principal for the authenticated user and adds it to the list of principals in the subject.
     */
    private void addPrincipal() {
        userPrincipal = new UsernamePrincipal(username);
        if (!subject.getPrincipals().contains(userPrincipal)) {
            subject.getPrincipals().add(userPrincipal);
        }
    }

    /**
     * Initializes the database login module.
     * 
     * @param subject the subject of the authentication request.
     * @param callbackHandler the callback handler used to obtain the username and password.
     * @param sharedState a map of state information that is shared among the various login modules.
     * @param options the configuration options that were specified for this login module.
     */
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options)
    {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
        extractKnownOptions();
        passwordEncrypter = new PasswordEncrypter(hashAlgorithm, characterEncoding);
        passwordValidator = new DatabasePasswordValidator(databaseDriverName, databaseUrl, databaseQuery);
    }

    /**
     * Extracts the known configuration options from the options map.
     */
    private void extractKnownOptions() {
        extractHashAlgorithm();
        extractCharacterEncoding();
        extractDatabaseDriverName();
        extractDatabaseUrl();
        extractDatabaseQuery();
    }

    /**
     * Extracts the database query from the options map.
     */
    private void extractDatabaseQuery() {
        Object databaseQuery = options.get("database.query");
        if (databaseQuery == null) {
            throw new IllegalArgumentException("missing required configuration parameter: database.query");
        }
        this.databaseQuery = databaseQuery.toString();
    }

    /**
     * Extracts the database URL from the options map.
     */
    private void extractDatabaseUrl() {
        Object databaseUrl = options.get("database.url");
        if (databaseUrl == null) {
            throw new IllegalArgumentException("missing required configuration parameter: database.url");
        }
        this.databaseUrl = databaseUrl.toString();
    }

    /**
     * Extracts the database driver name from the options map.
     */
    private void extractDatabaseDriverName() {
        Object databaseDriverName = options.get("database.driver");
        if (databaseDriverName == null) {
            throw new IllegalArgumentException("missing required configuration parameter: database.driver");
        }
        this.databaseDriverName = databaseDriverName.toString();
    }

    /**
     * Extracts the character encoding from the options map.
     */
    private void extractCharacterEncoding() {
        Object characterEncoding = options.get("character.encoding");
        if (characterEncoding != null) {
            this.characterEncoding = characterEncoding.toString();
        }
    }

    /**
     * Extracts the hash algorithm from the options map.
     */
    private void extractHashAlgorithm() {
        Object hashAlgorithm = options.get("hash.algorithm");
        if (hashAlgorithm != null) {
            this.hashAlgorithm = hashAlgorithm.toString();
        }
    }

    /**
     * Processes a login attempt. The return value of this method does not indicate success or failure. Instead, it
     * indicates whether or not this login module applies to the current login attempt. If this method returns false
     * then it means that this login module does not apply and this login module will be ignored.
     * 
     * @return true if the login attempt succeeds.
     * @throws loginException if the login attempt fails.
     */
    public boolean login() throws LoginException {
        initializeAuthenticationFields();
        validateCallbackHandler();
        getUsernameAndPassword();
        validateUsernameAndPassword();
        loginSucceeded = true;
        return true;
    }

    /**
     * Initializes the authentication fields.
     */
    private void initializeAuthenticationFields() {
        loginSucceeded = false;
        commitSucceeded = false;
        username = null;
        password = null;
        userPrincipal = null;
    }

    /**
     * Validates the callback handler that is being used. At this time, the only requirement is that the callback
     * handler is not null.
     * 
     * @throws LoginException if the callback handler is null.
     */
    private void validateCallbackHandler() throws LoginException {
        if (callbackHandler == null) {
            throw new LoginException("Error: no callback handler available");
        }
    }

    /**
     * Obtains the username and password.
     * 
     * @throws LoginException if the username and password can't be retrieved.
     */
    private void getUsernameAndPassword() throws LoginException {
        Callback[] callbacks = { new NameCallback("user name: "), new PasswordCallback("password: ", false) };
        try {
            callbackHandler.handle(callbacks);
            username = ((NameCallback) callbacks[0]).getName();
            char[] passwordChars = ((PasswordCallback) callbacks[1]).getPassword();
            if (passwordChars == null) {
                passwordChars = new char[0];
            }
            password = new String(passwordChars);
            ((PasswordCallback) callbacks[1]).clearPassword();
        }
        catch (IOException e) {
            throw new LoginException("unable to get username and password: " + e);
        }
        catch (UnsupportedCallbackException e) {
            throw new LoginException("Error: required callback not supported: " + e);
        }
    }

    /**
     * Validates the username and password.
     * 
     * @throws LoginException if the username and password are invalid or can't be validated.
     */
    private void validateUsernameAndPassword() throws LoginException {
        String encryptedPassword = passwordEncrypter.encryptPassword(password);
        passwordValidator.validatePassword(username, encryptedPassword);
    }

    /**
     * Logs the user out.
     * 
     * @return
     */
    public boolean logout() throws LoginException {
        validateStateForLogout();
        subject.getPrincipals().remove(userPrincipal);
        initializeAuthenticationFields();
        return true;
    }

    /**
     * Verifies that the user can be logged out.
     * 
     * @throws LoginException if the user can't be logged out.
     */
    private void validateStateForLogout() throws LoginException {
        if (!loginSucceeded || !commitSucceeded) {
            throw new LoginException("unable to log out a user who is not logged in");
        }
    }
}
