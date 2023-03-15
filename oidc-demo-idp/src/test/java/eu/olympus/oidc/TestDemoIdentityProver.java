package eu.olympus.oidc;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import eu.olympus.model.MFAInformation;
import java.util.Map;

import org.junit.Test;

import eu.olympus.model.Attribute;
import eu.olympus.oidc.model.DemoIdentityProof;
import eu.olympus.oidc.server.identityprovers.DemoIdentityProver;
import eu.olympus.server.interfaces.Storage;

public class TestDemoIdentityProver {
	
	@Test
	public void testIsValid() throws Exception {
		DemoIdentityProver prover = new DemoIdentityProver(null);
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("Se"));
		attributes.put("Age",new Attribute(30));
		DemoIdentityProof proof = new DemoIdentityProof("proof", attributes);
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
				assertEquals("user", username);
				assertTrue(attributes.containsKey("Name"));
				assertEquals(attributes.get("Name"), new Attribute("John Doe"));

				assertTrue(attributes.containsKey("Age"));
				assertEquals(attributes.get("Age"), new Attribute(30));

				attributeAdded = true;
			}

			@Override
			public void addAttribute(String username, String key, Attribute value) {
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
		
		DemoIdentityProver prover = new DemoIdentityProver(storage);
		
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("Name", new Attribute("John Doe"));
		attributes.put("Nationality", new Attribute("Se"));
		attributes.put("Age",new Attribute(30));
		DemoIdentityProof proof = new DemoIdentityProof("proof", attributes);
		
		prover.addAttributes(proof.getStringRepresentation(), "user");
		
		assertThat(storage.attributeAdded, is(true));
	}
	
}
