package eu.olympus.unit.server;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;
import java.io.IOException;

public class TestIdentityProver implements IdentityProver {

	private final Storage storage;

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
		} catch ( JsonProcessingException | OperationFailedException ignored) {
			throw new RuntimeException(ignored);
		}
	}

	public static IdentityProver getMock(Storage db) throws OperationFailedException {
		IdentityProver mock = mock(IdentityProver.class);
		doReturn(true).when(mock).isValid(anyString(),anyString());
		doAnswer(invocationOnMock -> {
			ObjectMapper mapper = new ObjectMapper();
			TestIdentityProof proof;
			try {
				String input = invocationOnMock.getArgument(0);
				String username = invocationOnMock.getArgument(1);
				proof = mapper.readValue(input, TestIdentityProof.class);
				db.addAttributes(username, proof.getAttributes());
			} catch (IOException ignored) {
			}
			return null;
		}).when(mock).addAttributes(anyString(),anyString());
		return mock;
	}


}
