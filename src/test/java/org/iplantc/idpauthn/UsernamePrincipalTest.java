package org.iplantc.idpauthn;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * Unit tests for org.iplantc.idpauthn.UsernamePrincipal.
 *
 * @author Dennis Roberts
 */
public class UsernamePrincipalTest {

    /**
     * Verifies that the constructor sets the name property.
     */
    @Test
    public void constructorShouldSetName() {
        UsernamePrincipal principal = new UsernamePrincipal("somename");
        assertEquals("somename", principal.getName());
    }

    /**
     * Verifies that we get an IllegalArgumentException if we try to instantiate an object with a null name.
     */
    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectNullName() {
        new UsernamePrincipal(null);
    }
    
    /**
     * Verifies that equals() detects identical principals.
     */
    @Test
    public void equalsShouldDetectIdenticalPrincipals() {
        UsernamePrincipal principal1 = new UsernamePrincipal("somename");
        UsernamePrincipal principal2 = new UsernamePrincipal("somename");
        assertTrue(principal1.equals(principal2));
    }
    
    /**
     * Verifies that equals() detects different principals.
     */
    @Test
    public void equalsShouldDetectDifferentPrincipals() {
        UsernamePrincipal principal1 = new UsernamePrincipal("somename");
        UsernamePrincipal principal2 = new UsernamePrincipal("someothername");
        assertFalse(principal1.equals(principal2));
    }
    
    /**
     * Verifies that equals() detects different objects.
     */
    @Test
    public void equalsShouldDetectDifferentObjects() {
        UsernamePrincipal principal = new UsernamePrincipal("somename");
        Object object = new Object();
        assertFalse(principal.equals(object));
    }
    
    /**
     * Verifies that the principal produces the correct hash code.
     */
    @Test
    public void hashCodeShouldGenerateCorrectHash() {
        UsernamePrincipal principal = new UsernamePrincipal("somename");
        assertEquals("somename".hashCode(), principal.hashCode());
    }

    /**
     * Verifies that toString() produces the correct value.
     */
    @Test
    public void toStringShouldProduceCorrectString() {
        UsernamePrincipal principal = new UsernamePrincipal("somename");
        assertEquals("somename", principal.toString());
    }
}
