package eu.olympus.client;

import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.model.exceptions.KeyGenerationFailedException;
import eu.olympus.model.exceptions.SigningFailedException;
import eu.olympus.util.ECKeyGenerator;
import eu.olympus.util.SoftwareCommonCrypto;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.List;
import java.util.Random;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ROM;

/**
 * Software implementation of the ClientCryptoModule used by PESTO. 
 *
 */
public class SoftwareClientCryptoModule extends SoftwareCommonCrypto implements ClientCryptoModule {

	private final BigInteger modulus;
	/**
	 * Constructor for the crypto module.
	 * @param random A RNG
	 * @param modulus The modulus of the RSA prime used for the RSA
	 * (vIdP) signing algorithm
	 */
	public SoftwareClientCryptoModule(Random random, BigInteger modulus) {
		super(random);
		this.modulus = modulus;
	}

	@Override
	public byte[] signECDSA(PrivateKey privateKey, List<byte[]> message) throws SigningFailedException{
		return signECDSA(privateKey, hashList(message));
	}

	@Override
	public byte[] signECDSA(PrivateKey privateKey, byte[] message) throws SigningFailedException{
		try {
			Signature sig = Signature.getInstance("SHA256withECDSA");
			sig.initSign(privateKey);
			sig.update(message);
			return sig.sign();
		} catch (Exception e){
			throw new SigningFailedException("Signing failed",e);
		}
	}

	@Override
	public KeyPair generateKeysFromBytes(byte[] bytes) throws KeyGenerationFailedException {
		return ECKeyGenerator.generateKey(bytes);
	}

	@Override
	public ECP hashAndMultiply(BIG r, byte[] password) {
		BIG order = new BIG(ROM.CURVE_Order);
		r.mod(order);
		return hashToGroup1Element(password).mul(r);
	}

	@Override
	public BigInteger getModulus() { return this.modulus; }

}
