package eu.olympus.cfp;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import eu.olympus.model.MFAInformation;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

import eu.olympus.cfp.model.UserCertificate;
import eu.olympus.cfp.server.CFPDatabaseFields;
import eu.olympus.cfp.server.identityprovers.UserCredentialIdentityProver;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.Storage;

public class TestUserCredentialIdentityProver {

	private UserCredentialIdentityProver prover;
	private Certificate ca = loadCertificate("src/test/resources/012345678A_PF_HSM_Test05.crt");

	@Ignore //TODO LOG must supply a valid cert+signing cert
	@Test
	public void testIsValid() throws Exception {
		Storage storage = new TestStorage();
		prover = new UserCredentialIdentityProver("src/test/resources/signerCertificate.cer", storage);
		
		UserCertificate certificate = new UserCertificate();
		certificate.setCert(ca);
		
		assertThat(prover.isValid(certificate.getStringRepresentation(), "user"), is(true));
	}
	
	@Test
	public void testAddAttribute() throws Exception {
		TestStorage storage = new TestStorage();
		prover = new UserCredentialIdentityProver("src/test/resources/signerCertificate.cer", storage);
		
		UserCertificate certificate = new UserCertificate();
		certificate.setCert(ca);
		
		prover.addAttributes(certificate.getStringRepresentation(), "user");
		
		assertThat(storage.attributeAdded, is(true));
	}
	
	private Certificate loadCertificate(String path) {
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(new File(path));
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		BufferedInputStream caInput = new BufferedInputStream(fis);
		
		Certificate ca = null;
		try {
			ca = cf.generateCertificate(caInput);
		} catch (CertificateException e) {
			e.printStackTrace();
		} finally {
			try {
				caInput.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return ca;
	}
	
	private class TestStorage implements Storage {

		public boolean attributeAdded = false;
		
		@Override
		public boolean hasUser(String username) {
			return true;
		}

		@Override
		public Map<String, Attribute> getAttributes(String username) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public void addAttributes(String username, Map<String, Attribute> attributes) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void addAttribute(String username, String key, Attribute value) {
			assertEquals(CFPDatabaseFields.USER_CERTIFICATE, key);
			UserCertificate certificate = new UserCertificate();
			certificate.setData(value.getAttr().toString());
			assertEquals(ca, certificate.getCert());
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
	
}
