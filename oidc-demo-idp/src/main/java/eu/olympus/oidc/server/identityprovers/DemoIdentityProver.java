package eu.olympus.oidc.server.identityprovers;

import eu.olympus.model.exceptions.OperationFailedException;
import java.io.IOException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.olympus.oidc.model.DemoIdentityProof;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;

/**
 * Token verifier. Adds the unique value of the token as a user attribute
 * Currently no verification is done, may involve a signature in the
 * future.
 *
 */
public class DemoIdentityProver implements IdentityProver {

	private Storage storage; 

	public DemoIdentityProver(Storage storage) {
		this.storage = storage;
	}

	//Only validates that the proof is a TokenIdentityProof
	@Override
	public boolean isValid(String input, String username) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			mapper.readValue(input, DemoIdentityProof.class);
		} catch (IOException e) {
			
			e.printStackTrace();
			return false;
		}
		return true;
	}


	@Override
	public void addAttributes(String input, String username) {
		ObjectMapper mapper = new ObjectMapper();
		DemoIdentityProof proof;
		try {
			proof = mapper.readValue(input, DemoIdentityProof.class);
			storage.addAttributes(username, proof.getAttributes());
		} catch (IOException | OperationFailedException e) {
			e.printStackTrace();
		}

	}
}
