package org.iplantc.idpauthn;

import java.security.Principal;

/**
 * Represents an authenticated principal.
 *
 * @author Dennis Roberts
 */
public class UsernamePrincipal implements Principal {
    
    /**
     * The name of the principal.
     */
    private String name;

    /**
     * Creates a new principal with the given name.
     *
     * @param name the new name.
     */
    public UsernamePrincipal(String name) {
        validateName(name);
        this.name = name;
    }

    /**
     * Validates a name.
     *
     * @param name the name to validate.
     */
    private void validateName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("name");
        }
    }

    /**
     * Determines whether or not this principal is equal to another object.
     */
    public boolean equals(Object otherObject) {
        if (otherObject instanceof UsernamePrincipal) {
            return name.equals(((UsernamePrincipal) otherObject).getName());
        }
        return false;
    }

    /**
     * Returns the principal name.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the hash code for this principal, which is always equal to the hash code of the principal name.
     * 
     * @return the hash code.
     */
    public int hashCode() {
        return name.hashCode();
    }

    /**
     * Produces a string representation of the principal.  For now, we're just returning the principal name.
     * 
     * @return the principal name.
     */
    public String toString() {
        return name;
    }
}
