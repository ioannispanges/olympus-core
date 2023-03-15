package eu.olympus.cfp;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import eu.olympus.model.MFAInformation;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import eu.olympus.cfp.model.CreditFile;
import eu.olympus.cfp.server.identityprovers.CreditFileIdentityProver;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.Storage;

public class TestCreditFileIdentityProver {

	private CreditFile proof;
	
	@Before
	public void loadArtifact() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/creditFileExample_v.2.enveloped.xml");
		BufferedReader br = new BufferedReader(new InputStreamReader(fis));
		StringBuilder bis = new StringBuilder();
		String line = br.readLine();
		while(line != null) {
			bis.append(line);
			bis.append('\n');
			line = br.readLine();
		}
		br.close();
		String rawXML = bis.toString();
		proof = new CreditFile();
		proof.setData(rawXML);
	}
	
	@Test
	public void testCFPIdentityProverIsValid() throws Exception {
		CreditFileIdentityProver prover = new CreditFileIdentityProver("src/test/resources/signerCertificate.cer", null);

		assertThat(prover.isValid(proof.getStringRepresentation(), "user"), is(true));
	}
	
	@Test
	public void testCFPIdentityProverAddAttributes() throws Exception {
		TestStorage storage = new TestStorage();
		CreditFileIdentityProver prover = new CreditFileIdentityProver("src/test/resources/signerCertificate.cer", storage);
		
		prover.addAttributes(proof.getStringRepresentation(), "test-user");

		assertEquals(new Attribute("BBVA"), storage.attributes.get("Nombre"));
		assertEquals(new Attribute("C11111111"), storage.attributes.get("Valor de documento"));
		assertEquals(new Attribute("N"), storage.attributes.get("Situacion de la empresa"));
		assertEquals(new Attribute("I98UU67EE568IO"), storage.attributes.get("Identificador electronico"));
		assertEquals(17, storage.attributes.size());
	}
		
	
	private class TestStorage implements Storage {

		public HashMap<String, Attribute> attributes = new HashMap<String, Attribute>();
		
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
			assertEquals("test-user", username);
			this.attributes.putAll(attributes);
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
	
}
