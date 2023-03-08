package eu.olympus.verifier;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import eu.olympus.verifier.interfaces.Verifier;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Simple class for verifying if a JSON Web Token
 * is signed by a specific RSA public key.
 *
 */
public class JWTVerifier implements Verifier {

	Algorithm algorithm;

	/**
	 * Instantiate the verifier
	 * @param pk The public key to use for verification
	 */
	public JWTVerifier(PublicKey pk){
		RSAKeyProvider provider = new RSAKeyProvider() {

			@Override
			public RSAPrivateKey getPrivateKey() {
				return null;
			}

			@Override
			public String getPrivateKeyId() {
				return null;
			}

			@Override
			public RSAPublicKey getPublicKeyById(String arg0) {
				return (RSAPublicKey)pk;
			}
		};
		
		this.algorithm = Algorithm.RSA256(provider);
	}
	

	@Override
	public boolean verify(String token) {
		com.auth0.jwt.JWTVerifier verifier = JWT.require(algorithm).build(); 
		try{
			verifier.verify(token);

			// Claims may be printed for debugging:
			// DecodedJWT jwt = verifier.verify(token);
			
			// for(String s: jwt.getClaims().keySet()){
			//    Do something with s
			// }
		}catch(SignatureVerificationException e) {
			return false;
		}
		return true;
	}

}
