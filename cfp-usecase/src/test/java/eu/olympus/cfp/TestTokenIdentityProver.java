package eu.olympus.cfp;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import eu.olympus.model.MFAInformation;
import java.util.Map;

import org.junit.Test;

import eu.olympus.cfp.model.TokenIdentityProof;
import eu.olympus.cfp.server.CFPDatabaseFields;
import eu.olympus.cfp.server.identityprovers.TokenIdentityProver;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.Storage;

public class TestTokenIdentityProver {

	private final String tokenValue = "THE SECRET TOKEN VALUE";
	
	@Test
	public void testIsValid() throws Exception {
		TokenIdentityProver prover = new TokenIdentityProver(null);
		TokenIdentityProof proof = new TokenIdentityProof(tokenValue);
		assertThat(prover.isValid(proof.getStringRepresentation(), "user"), is(true));
	}
	
	@Test
	public void testAddAttribute() throws Exception {
		class TestStorage implements Storage {

			public boolean attributeAdded = false;

			@Override
			public boolean hasUser(String username) {
				return true;
			}

			@Override
			public Map<String, Attribute> getAttributes(String username) {
				return null;
			}

			@Override
			public void addAttributes(String username, Map<String, Attribute> attributes) {
			}

			@Override
			public void addAttribute(String username, String key, Attribute value) {
				assertEquals(CFPDatabaseFields.USER_TOKEN, key);
				assertEquals(new Attribute(tokenValue), value);
				attributeAdded = true;
			}

			@Override
			public boolean deleteAttribute(String username, String attributeName) {
				// TODO Auto-generated method stub
				return false;
			}

			@Override
			public boolean deleteUser(String username) {
				// TODO Auto-generated method stub
				return false;
			}

			@Override
			public void assignMFASecret(String username, String type, String secret) {

			}

			@Override
			public Map<String, MFAInformation> getMFAInformation(String username) {
				return null;
			}

			@Override
			public void activateMFA(String username, String type) {

			}

			@Override
			public void deleteMFA(String username, String type) {

			}

			@Override
			public long getLastAuthAttempt(String username) {
				return 0;
			}

			@Override
			public int getNumberOfFailedAuthAttempts(String username) {
				return 0;
			}

			@Override
			public void failedAuthAttempt(String username) {

			}

			@Override
			public void clearFailedAuthAttempts(String username) {

			}

			@Override
			public int getNumberOfFailedMFAAttempts(String username) {
				return 0;
			}

			@Override
			public void failedMFAAttempt(String username) {

			}

			@Override
			public void clearFailedMFAAttempts(String username) {

			}

			@Override
			public long getLastMFAAttempt(String username) {
				return 0;
			}

		};
		TestStorage storage = new TestStorage();
		
		TokenIdentityProver prover = new TokenIdentityProver(storage);
		TokenIdentityProof proof = new TokenIdentityProof();
		proof.setValue(tokenValue);

		prover.addAttributes(proof.getStringRepresentation(), "user");
		
		assertThat(storage.attributeAdded, is(true));
	}
	
}
