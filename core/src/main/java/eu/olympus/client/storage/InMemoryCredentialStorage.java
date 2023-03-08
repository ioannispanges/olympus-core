package eu.olympus.client.storage;

import eu.olympus.client.interfaces.CredentialStorage;
import eu.olympus.model.PSCredential;

public class InMemoryCredentialStorage implements CredentialStorage {

    private PSCredential currentCredential;

    @Override
    public void storeCredential(PSCredential credential) {
        currentCredential=credential;
    }

    @Override
    public PSCredential getCredential() {
        return currentCredential;
    }

    @Override
    public boolean checkCredential() {
        if (currentCredential == null)
            return false;
        if (currentCredential.getEpoch() < System.currentTimeMillis()) {
            // Credential expired, safely delete
            deleteCredential();
            return false;
        }
        return true;
    }

    @Override
    public void deleteCredential() {
        currentCredential=null;
    }
}
