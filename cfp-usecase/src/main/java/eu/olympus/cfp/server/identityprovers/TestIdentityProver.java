package eu.olympus.cfp.server.identityprovers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.cfp.model.TestIdentityProof;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;

import java.io.IOException;

public class TestIdentityProver implements IdentityProver {

	private Storage storage;

	public TestIdentityProver(Storage storage) {
		super();
		this.storage = storage;
	}

	@Override
	public boolean isValid(String proof, String username) {
		return true;
	}

	@Override
	public void addAttributes(String input, String username) {
		ObjectMapper mapper = new ObjectMapper();
		TestIdentityProof proof;
		try {
			proof = mapper.readValue(input, TestIdentityProof.class);
			storage.addAttributes(username, proof.getAttributes());
		} catch (IOException | OperationFailedException e) {
		}
	}

}
