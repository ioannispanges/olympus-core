package eu.olympus.util;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.SerializedKey;
import eu.olympus.util.psmultisign.PSverfKey;

public class KeySerializer {

	private KeySerializer(){
	}
	
	public static SerializedKey serialize(PublicKey key){
		return new SerializedKey(key.getAlgorithm(), key.getFormat(), Base64.getEncoder().encodeToString(key.getEncoded()));
	}
	
	public static SerializedKey serialize(PrivateKey key){
		return new SerializedKey(key.getAlgorithm(), key.getFormat(), Base64.getEncoder().encodeToString(key.getEncoded()));
	}
	
	
	public static Key deSerialize(SerializedKey key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		if("RSA".equals(key.getAlgorithm())) {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			if("X.509".equals(key.getFormat())) {
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getEncoded()));
				return factory.generatePublic(x509EncodedKeySpec);
			}
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getEncoded()));
			return factory.generatePrivate(pkcs8EncodedKeySpec);
		}
		if("EC".equals(key.getAlgorithm())){
			KeyFactory factory = KeyFactory.getInstance("EC");
			if("X.509".equals(key.getFormat())) {
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getEncoded()));
				return factory.generatePublic(x509EncodedKeySpec);
			}
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getEncoded()));
			return factory.generatePrivate(pkcs8EncodedKeySpec);
		}
		if("PS".equals(key.getAlgorithm())){
			try {
				return new PSverfKey(Base64.getDecoder().decode(key.getEncoded()));
			} catch (InvalidProtocolBufferException e) {
				throw new InvalidKeyException("PS key could not be recovered");
			}
		}
		throw new InvalidKeyException(key.getAlgorithm()+" is not a supported algorithm type");
	}
	
}
