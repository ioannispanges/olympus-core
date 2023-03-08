package eu.olympus.client.interfaces;

import eu.olympus.model.PSCredential;

public interface CredentialStorage {

    void storeCredential(PSCredential credential);

    PSCredential getCredential();

    boolean checkCredential();

    void deleteCredential();
}
