package eu.olympus.util;

import eu.olympus.model.exceptions.KeyGenerationFailedException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public class ECKeyGenerator {

	private ECKeyGenerator() {}
	
	public static KeyPair generateKey(byte[] seed) throws KeyGenerationFailedException {
		try{

		Security.addProvider(new BouncyCastleProvider());
		KeyFactory factory = KeyFactory.getInstance("EC", "BC");
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("SecP256r1");
		
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(seed, "HmacSHA256"));
		mac.update((byte)0);
		byte[] bytes = mac.doFinal();
		BigInteger s = new BigInteger(bytes).mod(params.getCurve().getOrder()); 
		ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(s, params);
		PrivateKey gpk = factory.generatePrivate(privateSpec);
		ECPoint q = params.getG().multiply(s); //G*s is the public key!
		ECPublicKeySpec pubKey = new ECPublicKeySpec(q, params);
		PublicKey gpuk = factory.generatePublic(pubKey);

		return new KeyPair(gpuk, gpk);

		} catch (Exception e){
			throw new KeyGenerationFailedException("Failed to generate key",e);
		}
	}
	
}
