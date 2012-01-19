package org.iplantc.idpauthn;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * Unit tests for org.iplantc.idpauthn.DatabasePasswordValidator.
 *
 * @author Dennis Roberts
 */
public class DatabasePasswordValidatorTest {

    /**
     * Creates the default database password validator for use in most of our tests.
     *
     * @return the database password validator.
     */
    private DatabasePasswordValidator createDefaultValidator() {
        String original = "SELECT * FROM user_table WHERE username = $[username] AND password = $[password]";
        DatabasePasswordValidator validator = new DatabasePasswordValidator("some.bogus.Driver", "url", original);
        return validator;
    }

    /**
     * Verifies that we get an exception if we attempt to create a database password validator without a driver.
     */
    @Test(expected=IllegalArgumentException.class)
    public void constructorShouldRejectNullDriver() {
        new DatabasePasswordValidator(null, "url", "query");
    }
    
    /**
     * Verifies that we get an exception if we attempt to create a database password validator without a URL. 
     */
    @Test(expected=IllegalArgumentException.class)
    public void constructorShouldRejectNullUrl() {
        new DatabasePasswordValidator("some.bogus.Driver", null, "query");
    }

    /**
     * Verifies that we get an exception if we attempt to create a database password validator without a query.
     */
    @Test(expected=IllegalArgumentException.class)
    public void constructorShouldRejectNullQuery() {
        new DatabasePasswordValidator("some.bogus.Driver", "url", null);
    }

    /**
     * Verifies that the constructor sets the URL.
     */
    @Test
    public void constructorShouldSetUrl() {
        DatabasePasswordValidator validator = createDefaultValidator();
        assertEquals("url", validator.getUrl());
    }

    /**
     * Verifies that the constructor sets the driver name.
     */
    @Test
    public void constructorShouldSetDriverName() {
        DatabasePasswordValidator validator = createDefaultValidator();
        assertEquals("some.bogus.Driver", validator.getDriverName());
    }

    /**
     * Verifies that a query can be parsed.
     */
    @Test
    public void constructorShouldParseAnnotatedQuery() {
        DatabasePasswordValidator validator = createDefaultValidator();
        assertEquals("SELECT * FROM user_table WHERE username = ? AND password = ?", validator.getQuery());
    }

    /**
     * Verifies that the validator is able to correctly identify the argument number for the username argument.
     */
    @Test
    public void constructorShouldIdentifyUsernameLocation() {
        DatabasePasswordValidator validator = createDefaultValidator();
        assertEquals(1, validator.getUsernameArgumentNumber());
    }
 
    /**
     * Verifies that the validator is able to correctly identify the argument number for the password argument.
     */
    @Test
    public void constructorShouldIdentifyPasswordLocation() {
        DatabasePasswordValidator validator = createDefaultValidator();
        assertEquals(2, validator.getPasswordArgumentNumber());
    }
    
    /**
     * Verifies that the validator rejects queries containing arguments that it doesn't know about.
     */
    @Test(expected=IllegalArgumentException.class)
    public void constructorShouldRejectQueriesWithUnknownArguments() {
        String query = "SELECT * FROM user_table WHERE some_field = $[iamthecagemaster]";
        new DatabasePasswordValidator("some.bogus.Driver", "url", query);
    }
}
