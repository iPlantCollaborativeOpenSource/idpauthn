package org.iplantc.idpauthn;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.iplantc.idpauthn.mock.MockCallbackHandler;
import org.iplantc.idpauthn.mock.MockPasswordValidator;
import org.iplantc.securitytoolkit.PasswordEncrypter;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for org.iplantc.idpauthn.DatabaseLogin.
 * 
 * @author Dennis Roberts
 */
public class DatabaseLoginTest {

    /**
     * The subject of the login attempt.
     */
    private Subject subject;

    /**
     * The callback handler used to obtain the username and password.
     */
    private MockCallbackHandler callbackHandler;

    /**
     * Shared state information that is shared among the various login modules.
     */
    private Map<String, String> sharedState;

    /**
     * Login module configuration options.
     */
    private Map<String, String> options;

    /**
     * Used to validate the user's credentials.
     */
    private MockPasswordValidator passwordValidator;

    /**
     * The object instance to be used in all of the tests.
     */
    private DatabaseLogin instance;

    /**
     * The query that will be specified in the options.
     */
    private String databaseQuery = "SELECT something FROM somewhere WHERE who = $[username] AND what = $[password]";

    /**
     * The database driver that will be specified in the options.
     */
    private String databaseDriver = "com.mysql.jdbc.Driver";

    /**
     * The database URL that will be specified in the options.
     */
    private String databaseUrl = "jdbc:mysql://foo";

    /**
     * Adds the required options to the options hash.
     */
    private void addRequiredOptions() {
        options.put("database.driver", databaseDriver);
        options.put("database.url", databaseUrl);
        options.put("database.query", databaseQuery);
    }

    /**
     * Initializes each test.
     */
    @Before
    public void initialize() {
        subject = new Subject();
        callbackHandler = new MockCallbackHandler();
        sharedState = new HashMap<String, String>();
        options = new HashMap<String, String>();
        passwordValidator = new MockPasswordValidator();
        instance = new DatabaseLogin();
        addRequiredOptions();
    }

    /**
     * Verifies that the password hash algorithm defaults to "SHA-512".
     */
    @Test
    public void hashAlgorithmShouldDefaultToSha512() {
        initializeInstance();
        assertEquals("SHA-512", instance.getHashAlgorithm());
    }

    /**
     * Verifies that the character encoding defaults to "UTF-8".
     */
    @Test
    public void characterEncodingShouldDefaultToUtf8() {
        initializeInstance();
        assertEquals("UTF-8", instance.getCharacterEncoding());
    }

    /**
     * Verifies that we can specify the hash algorithm.
     */
    @Test
    public void shouldBeAbleToSpecifyHashAlgorithm() {
        options.put("hash.algorithm", "215-AHS");
        initializeInstance();
        assertEquals("215-AHS", instance.getHashAlgorithm());
    }

    /**
     * Verifies that we can specify the character encoding.
     */
    @Test
    public void shouldBeAbleToSpecifyCharacterEncoding() {
        options.put("character.encoding", "UTF-16");
        initializeInstance();
        assertEquals("UTF-16", instance.getCharacterEncoding());
    }

    /**
     * Verifies that the callback handler's handle() method is called when a login is attempted.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void shouldHandleCallbacks() throws LoginException {
        initializeInstance();
        instance.login();
        assertTrue(callbackHandler.getHandleCalled());
    }

    /**
     * Verifies that the password validator's validatePassword() method is called when a login is attempted.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void shouldCallValidatePassword() throws LoginException {
        initializeInstance();
        instance.login();
        assertTrue(passwordValidator.getValidatePasswordCalled());
    }

    /**
     * Verifies that the username is passed to the password validator in plain text.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void plaintextUsernamePassedToPasswordValidator() throws LoginException {
        initializeInstance();
        instance.login();
        assertEquals("nameofsomeuser", passwordValidator.getUsername());
    }

    /**
     * Verifies that the encrypted password is passed to the password validator.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void encryptedPasswordPassedToPasswordValidator() throws LoginException {
        initializeInstance();
        instance.login();
        String expected = new PasswordEncrypter("SHA-512", "UTF-8").encryptPassword("passwordofsomeuser");
        assertEquals(expected, passwordValidator.getEncryptedPassword());
    }

    /**
     * Verifies that we get a LoginException if an IOException is thrown during a login attempt.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test(expected = LoginException.class)
    public void shouldGetLoginExceptionIfIoExceptionThrown() throws LoginException {
        initializeInstance();
        callbackHandler.setThrowIoException(true);
        instance.login();
    }

    /**
     * Verifies that we get a LoginException if an UnsupportedCallbackException is thrown during a login attempt.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test(expected = LoginException.class)
    public void shouldGetLoginExceptionIfUnsupportedCallbackExceptionThrown() throws LoginException {
        initializeInstance();
        callbackHandler.setRejectCallbacks(true);
        instance.login();
    }

    /**
     * Verifies that we get a LoginException if the username and password are rejected by the password validator.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test(expected = LoginException.class)
    public void shouldGetLoginExceptionForBousUsernameAndPassword() throws LoginException {
        initializeInstance();
        passwordValidator.setAcceptPassword(false);
        instance.login();
    }

    /**
     * Verifies that we get a LoginException if the callback handler is null.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test(expected = LoginException.class)
    public void shouldGetLoginExceptionIfCallbackHandlerIsNull() throws LoginException {
        instance.initialize(subject, null, sharedState, options);
        instance.setPasswordValidatorForTesting(passwordValidator);
        instance.login();
    }

    /**
     * Verifies that commit returns false if the login attempt didn't succeed.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void commitShouldReturnFalseIfUserNotLoggedIn() throws LoginException {
        initializeInstance();
        assertFalse(instance.commit());
    }

    /**
     * Verifies that commit returns true if the login attempt succeeded.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void commitShouldReturnTrueIfUserLoggedIn() throws LoginException {
        initializeInstance();
        instance.login();
        assertTrue(instance.commit());
    }

    /**
     * Verifies that commit add the principal to the subject.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void commitShouldAddPrincipal() throws LoginException {
        initializeInstance();
        instance.login();
        instance.commit();
        assertTrue(subject.getPrincipals().contains(new UsernamePrincipal("nameofsomeuser")));
    }

    /**
     * Verifies that abort returns false if the login attempt didn't succeed.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void abortShouldReturnFalseIfUserNotLoggedIn() throws LoginException {
        initializeInstance();
        assertFalse(instance.abort());
    }

    /**
     * Verifies that abort returns true if the login attempt succeeded.
     * 
     * @throws LoginException if the login attempt fails.
     */
    @Test
    public void abortShouldReturnTrueIfUserLoggedIn() throws LoginException {
        initializeInstance();
        instance.login();
        assertTrue(instance.abort());
    }

    /**
     * Verifies that we get an exception if there's an attempt to log out a user who has not logged in.
     * 
     * @throws LoginException if the user can't be logged out.
     */
    @Test(expected = LoginException.class)
    public void logoutShouldFailIfUserNotLoggedIn() throws LoginException {
        initializeInstance();
        instance.logout();
    }

    /**
     * Verifies that we get an exception if there's an attempt to log out a user before the authentication process has
     * been committed.
     * 
     * @throws LoginException if the user can't be logged out.
     */
    @Test(expected = LoginException.class)
    public void logoutShouldFailIfAuthenticationProcessNotCommitted() throws LoginException {
        initializeInstance();
        instance.login();
        instance.logout();
    }

    /**
     * Verifies that we get an exception if there's an attempt to logout a user after the authentication process has
     * been aborted.
     * 
     * @throws LoginException if the user can't be logged out.
     */
    @Test(expected = LoginException.class)
    public void logoutShouldFailIfAuthenticationProcessAborted() throws LoginException {
        initializeInstance();
        instance.login();
        instance.abort();
        instance.logout();
    }

    /**
     * Verifies that logout succeeds when the authentication process has completed successfully.
     * 
     * @throws LoginException if the user can't be logged out.
     */
    @Test
    public void logoutShouldSucceed() throws LoginException {
        initializeInstance();
        instance.login();
        instance.commit();
        assertTrue(instance.logout());
    }

    /**
     * Verifies that the databaseDriverName property is set when the login module is initialized.
     */
    @Test
    public void initializeShouldSetDatabaseDriverName() {
        initializeInstance();
        assertEquals(databaseDriver, instance.getDatabaseDriverName());
    }

    /**
     * Verifies that we get an exception if the database driver name is not specified in the options.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initializeShouldRejectMissingDatabaseDriverName() {
        options.remove("database.driver");
        initializeInstance();
    }

    /**
     * Verifies that the databaseUrl property is set when the login module is initialized.
     */
    @Test
    public void initializeShouldSetDatabaseUrl() {
        initializeInstance();
        assertEquals(databaseUrl, instance.getDatabaseUrl());
    }

    /**
     * Verifies that we get an exception if the database URL is not specified in the options.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initializeShouldRejectMissingDatabaseUrl() {
        options.remove("database.url");
        initializeInstance();
    }

    /**
     * Verifies that the databaseQuery property is set when the login module is initialized.
     */
    @Test
    public void initializeShouldSetDatabaseQuery() {
        initializeInstance();
        assertEquals(databaseQuery, instance.getDatabaseQuery());
    }

    /**
     * Verifies that we get an exception if the database query is not specified in the options.
     */
    @Test(expected = IllegalArgumentException.class)
    public void initializeShouldRejectMissingDatabaseQuery() {
        options.remove("database.query");
        initializeInstance();
    }

    /**
     * Initializes the DatabaseLogin instance.
     */
    private void initializeInstance() {
        instance.initialize(subject, callbackHandler, sharedState, options);
        instance.setPasswordValidatorForTesting(passwordValidator);
    }
}
