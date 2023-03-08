package eu.olympus.server;

import eu.olympus.model.Attribute;
import eu.olympus.model.Policy;
import eu.olympus.model.exceptions.AuthenticationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.storage.InMemoryKeyDB;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;

public class PasswordJWTIdP extends AbstractPasswordIdP {

	private JWTTokenGenerator tokenGenerator;
	private Certificate cert;
	
	public PasswordJWTIdP(Storage database, List<IdentityProver> identityProvers, Map<String, MFAAuthenticator> mfaAuthenticators){
		if (database != null) {
			try{
				authenticationHandler = new PasswordHandler(database, new SoftwareServerCryptoModule(new Random(1)) , new InMemoryKeyDB(), mfaAuthenticators);
				for(IdentityProver prover: identityProvers) {
					authenticationHandler.addIdentityProver(prover);
				}
				tokenGenerator = new JWTTokenGenerator();
			}catch(Exception e) {
				throw new IllegalArgumentException(e);
			}
		}
	}
	
	public void setup(RSAPrivateKey privKey, Certificate certificate) throws SetupException, Exception {
		try {
			tokenGenerator.setKeys(privKey, (RSAPublicKey) certificate.getPublicKey());
			this.cert = certificate;
		} catch (IllegalArgumentException e){
			throw new SetupException("Failed to set token generator keys",e);
		}
	}

	public String authenticate(String username, byte[] cookie, Policy policy) throws AuthenticationFailedException {
		if(validateSession(Base64.encodeBase64String(cookie))) {
			try{
				Map<String, Attribute> assertions = authenticationHandler
						.validateAssertions(username, policy);
				return tokenGenerator.generateToken(assertions);
			} catch(Exception e) {
				//Do some handling of un-instantiated calls to tokenGenerator
				throw new AuthenticationFailedException("Failed : IdP not initialized",e);
			}
		}
		throw new AuthenticationFailedException("Authentication failed");
	}

	@Override
	public Certificate getCertificate() {
		return cert;
	}

	@Override
	public int getId() {
		// Only one server so its ID is 0
		return 0;
	}
}
