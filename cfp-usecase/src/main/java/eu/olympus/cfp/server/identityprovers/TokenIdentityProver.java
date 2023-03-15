package eu.olympus.cfp.server.identityprovers;

import eu.olympus.model.exceptions.OperationFailedException;
import java.io.IOException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.olympus.cfp.model.TokenIdentityProof;
import eu.olympus.cfp.server.CFPDatabaseFields;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;

/**
 * Token verifier. Adds the unique value of the token as a user attribute
 * Currently no verification is done, may involve a signature in the
 * future.
 *
 */
public class TokenIdentityProver implements IdentityProver {

	private Storage storage; 

	public TokenIdentityProver(Storage storage) {
		this.storage = storage;
	}

	//Only validates that the proof is a TokenIdentityProof
	@Override
	public boolean isValid(String input, String username) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			mapper.readValue(input, TokenIdentityProof.class);
		} catch (Exception e) {
			//e.printStackTrace();
			return false;
		}
		return true;
	}


	@Override
	public void addAttributes(String input, String username) throws OperationFailedException {
		ObjectMapper mapper = new ObjectMapper();
		TokenIdentityProof proof;
		try {
			proof = mapper.readValue(input, TokenIdentityProof.class);
			storage.addAttribute(username, CFPDatabaseFields.USER_TOKEN, new Attribute(proof.getValue()));
		} catch (IOException e) {
			//Should never be reached, validation has been done in previous step
		}

	}
}
