package datawave.security.evidence;

import datawave.security.authorization.DatawaveUser;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.Evidence;

import java.util.Collection;
import java.util.Collections;

/**
 * Represents information found in the datawave system for a particular user after an authentication attempt against provided evidence.
 */
public class EvidenceIdentity {
    
    private final Collection<DatawaveUser> users;
    private final Attributes attributes;
    
    public EvidenceIdentity(Collection<DatawaveUser> users) {
        this(users, Attributes.EMPTY);
    }
    
    public EvidenceIdentity(Collection<DatawaveUser> users, Attributes attributes) {
        this.users = Collections.unmodifiableCollection(users);
        this.attributes = attributes;
    }
    
    /**
     * Return the collection of users derived from evidence. Possibly empty, but never null.
     * @return the users
     */
    public Collection<DatawaveUser> getUsers() {
        return users;
    }
    
    /**
     * Return attributes derived from evidence.
     * @return the attributes
     */
    public Attributes getAttributes() {
        return attributes;
    }
}
