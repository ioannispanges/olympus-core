package eu.olympus.server.interfaces;

import eu.olympus.model.exceptions.OperationFailedException;

public interface IdentityProver {

	public boolean isValid(String idProof, String username);

	public void addAttributes(String proof, String username) throws OperationFailedException;
}
