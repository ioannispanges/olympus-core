package eu.olympus.cfp.server.identityprovers;

import eu.olympus.model.exceptions.OperationFailedException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.olympus.cfp.model.UserCertificate;
import eu.olympus.cfp.server.CFPDatabaseFields;
import eu.olympus.model.Attribute;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;


/**
 * Verifies that a user certificate is signed by a trusted certificate
 *
 */
public class UserCredentialIdentityProver implements IdentityProver {

	private KeyStore trustAnchors;
	private Storage storage;

	/**
	 * TODO: handle certficate/keystores nicer
	 * @param pathToCertificate
	 * @throws Exception
	 */
	public UserCredentialIdentityProver(String pathToCertificate, Storage storage) throws Exception {
		this.storage = storage;
        
        FileInputStream fis = new FileInputStream(pathToCertificate);
        BufferedInputStream bis = new BufferedInputStream(fis);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        java.security.cert.Certificate cert = null;
        while (bis.available() > 0) {
            cert = cf.generateCertificate(bis);
        }

        trustAnchors = KeyStore.getInstance("JKS");
        trustAnchors.load(null, null);
        trustAnchors.setCertificateEntry("CFP", cert);
	}
	
	//TODO We need to verify that verification is working
	@Override
	public boolean isValid(String input, String username) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			UserCertificate proof = mapper.readValue(input, UserCertificate.class);
			// To check the validity of the dates
			X509Certificate cert = (X509Certificate)proof.getCert();
			cert.checkValidity();
			//Check the chain
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			List<X509Certificate> mylist = new ArrayList<X509Certificate>();          
			mylist.add(cert);
			CertPath cp = cf.generateCertPath(mylist);
			
			PKIXParameters params = new PKIXParameters(trustAnchors);
	
			params.setRevocationEnabled(false);
			CertPathValidator cpv =
			      CertPathValidator.getInstance(CertPathValidator.getDefaultType());
			PKIXCertPathValidatorResult pkixCertPathValidatorResult =
			      (PKIXCertPathValidatorResult) cpv.validate(cp, params);
			System.out.println("done... "+pkixCertPathValidatorResult.getPublicKey());
		} catch(Exception e) {
			//e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public void addAttributes(String input, String username) throws OperationFailedException {
		try {
			ObjectMapper mapper = new ObjectMapper();
			UserCertificate proof = mapper.readValue(input, UserCertificate.class);
			storage.addAttribute(username, CFPDatabaseFields.USER_CERTIFICATE, new Attribute(proof.getData()));
		} catch(JsonProcessingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
