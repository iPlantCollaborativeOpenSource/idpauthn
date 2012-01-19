package org.iplantc.idpauthn;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

/**
 * A password validator that validates the username and password against a relational database table. The SQL query may
 * be specified using an extended SQL syntax in which named arguments are specified using the notation
 * <code>$[arg_name]</code> where <code>arg_name</code> is the name of the query argument. For example, the following
 * query can be used to verify that the username and password exist in the user_table table:
 * 
 * <p>
 * 
 * <pre>
 * <code>
 *     SELECT * FROM user_table WHERE username = $[username] AND password = $[password]
 * </code>
 * </pre>
 * 
 * </p>
 * 
 * <p>
 * The selected argument name must be recognized for the database password validator to be able to handle the query. The
 * currently known argument names are <code>username</code> and <code>password</code>.
 * </p>
 * 
 * <p>
 * The user is authenticated based on whether or not the query produces results. This means that both the username and
 * the password should be included in the WHERE clause of the query. Otherwise, unintended authentications are likely to
 * occur.
 * </p>
 * 
 * @author Dennis Roberts
 */
public class DatabasePasswordValidator implements PasswordValidator {

    /**
     * The regular expression used to identify query arguments.
     */
    private static final Pattern QUERY_ARGUMENT_PATTERN = Pattern.compile("\\$\\[([^\\]]+)\\]");

    /**
     * The argument name to use for the username argument.
     */
    private static final String USERNAME_ARGUMENT_NAME = "username";

    /**
     * The argument name to use for the password argument.
     */
    private static final String PASSWORD_ARGUMENT_NAME = "password";

    /**
     * The name of the driver used to connect to the database.
     */
    private String driverName = null;

    /**
     * The URL use to connect to the database.
     */
    private String url = null;

    /**
     * The query to execute.
     */
    private String query = null;

    /**
     * A container for the username argument number.
     */
    private ArgumentNumberHolder usernameArgumentNumber = new ArgumentNumberHolder();

    /**
     * A container for the password argument number.
     */
    private ArgumentNumberHolder passwordArgumentNumber = new ArgumentNumberHolder();

    /**
     * A hash table that maps argument names to their respective argument number containers. This hash makes it easier
     * to implement the code that parses the query. Note that in order to add support for another named argument,
     * another argument number holder needs to be added, this hash needs to be updated and isPasswordValid needs to be
     * updated to recognize the new argument.
     */
    @SuppressWarnings("serial")
    private final HashMap<String, ArgumentNumberHolder> KNOWN_ARGUMENTS = new HashMap<String, ArgumentNumberHolder>()
    {
        {
            put(USERNAME_ARGUMENT_NAME, usernameArgumentNumber);
            put(PASSWORD_ARGUMENT_NAME, passwordArgumentNumber);
        }
    };

    /**
     * The getter for the query property.
     * 
     * @return the query.
     */
    public String getQuery() {
        return query;
    }

    /**
     * The getter for the url property.
     *
     * @return the URL.
     */
    public String getUrl() {
        return url;
    }

    /**
     * The getter for the driverName property.
     * 
     * @return the driver name.
     */
    public String getDriverName() {
        return driverName;
    }

    /**
     * The getter for the username argument number.
     * 
     * @return the argument number.
     */
    public int getUsernameArgumentNumber() {
        return usernameArgumentNumber.getArgumentNumber();
    }

    /**
     * The getter for the password argument number.
     * 
     * @return the argument number.
     */
    public int getPasswordArgumentNumber() {
        return passwordArgumentNumber.getArgumentNumber();
    }

    /**
     * Creates a new database password validator for the given query.
     * 
     * @param driverName the name of the JDBC driver to use to establish the connection.
     * @param url the URL used to connect to the database.
     * @param annotatedQuery the query with named arguments as described in the documentation for this class.
     */
    public DatabasePasswordValidator(String driverName, String url, String annotatedQuery) {
        verifyNotNull(driverName, "no driver name provided");
        verifyNotNull(url, "no database connection url provided");
        verifyNotNull(annotatedQuery, "no query provided");
        this.url = url;
        this.driverName = driverName;
        query = parseAnnotatedQuery(annotatedQuery);
    }

    /**
     * Verifies that a required argument is not null.
     * 
     * @param argument the argument to validate.
     * @param msg the message to include in the exception if the argument is null.
     */
    private void verifyNotNull(Object argument, String msg) {
        if (argument == null) {
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Parses an annotated query by replacing named arguments with SQL argument placeholders (question marks) and noting
     * the relative positions of the arguments in the query. An IllegalArgumentException will be thrown if an argument
     * with an unrecognized name is encountered.
     * 
     * @param annotatedQuery the query to parse.
     * @return the query in standard SQL syntax.
     */
    private String parseAnnotatedQuery(String annotatedQuery) {
        StringBuffer buffer = new StringBuffer();
        Matcher matcher = QUERY_ARGUMENT_PATTERN.matcher(annotatedQuery);
        int argumentNumber = 0;
        while (matcher.find()) {
            argumentNumber++;
            storeArgumentNumber(matcher.group(1), argumentNumber);
            matcher.appendReplacement(buffer, "?");
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }

    /**
     * Records the relative position of a named argument in the query. An IllegalArgumentException will be thrown if an
     * argument with an unrecognized name is encountered.
     * 
     * @param argumentName the argument name.
     * @param argumentNumber the argument position.
     */
    private void storeArgumentNumber(String argumentName, int argumentNumber) {
        ArgumentNumberHolder argumentNumberHolder = KNOWN_ARGUMENTS.get(argumentName);
        if (argumentNumberHolder == null) {
            throw new IllegalArgumentException("unknown query argument " + argumentName);
        }
        argumentNumberHolder.setArgumentNumber(argumentNumber);
    }

    /**
     * Validates the given username and encrypted password.
     * 
     * @param username the username to validate.
     * @param encryptedPassword the encrypted version of the password to validate.
     * @throws LoginException if the login fails for any reason.
     */
    public void validatePassword(String username, String encryptedPassword) throws LoginException {
        loadJdbcDriver();
        if (!isPasswordValid(username, encryptedPassword)) {
            throw new FailedLoginException();
        }
    }

    /**
     * Determines whether or not a username and password are valid.
     * 
     * @param username the username.
     * @param encryptedPassword the encrypted password to validate.
     * @return true if the username and password are valid.
     * @throws LoginException if we're unable to query the database.
     */
    private boolean isPasswordValid(String username, String encryptedPassword) throws LoginException {
        Connection connection = null;
        try {
            connection = DriverManager.getConnection(url);
            PreparedStatement statement = connection.prepareStatement(query);
            setArgument(statement, usernameArgumentNumber.getArgumentNumber(), username);
            setArgument(statement, passwordArgumentNumber.getArgumentNumber(), encryptedPassword);
            ResultSet resultSet = statement.executeQuery();
            return resultSet.next() ? true : false;
        }
        catch (SQLException e) {
            throw new LoginException("unable to query the user database: " + e);
        }
        finally {
            if (connection != null) {
                try {
                    connection.close();
                }
                catch (SQLException ignore) {
                }
            }
        }
    }

    /**
     * Sets a positional string argument in the given prepared statement. The position of the argument may be equal to
     * or less than zero in which case, the argument will be ignored.
     * 
     * @param statement the prepared statement.
     * @param position the position of the argument in the prepared statement.
     * @param value the argument value.
     * @throws SQLException
     */
    private void setArgument(PreparedStatement statement, int position, String value) throws SQLException {
        if (position > 0) {
            statement.setString(position, value);
        }
    }

    /**
     * Loads the JDBC driver.
     */
    private void loadJdbcDriver() throws LoginException {
        try {
            Class.forName(driverName);
        }
        catch (ClassNotFoundException e) {
            throw new LoginException("uanable to load the JDBC driver: " + e);
        }
    }
}

/**
 * A simple container for an argument number in a query.
 */
class ArgumentNumberHolder {

    /**
     * The argument number.
     */
    private int argumentNumber = 0;

    /**
     * The getter for the argument number.
     * 
     * @return the argument number.
     */
    public int getArgumentNumber() {
        return argumentNumber;
    }

    /**
     * The setter for the argument number.
     * 
     * @param argumentNumber the argument number.
     */
    public void setArgumentNumber(int argumentNumber) {
        this.argumentNumber = argumentNumber;
    }
}
