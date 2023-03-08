package eu.olympus.server.interfaces;

import eu.olympus.util.CommonCrypto;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.List;

import eu.olympus.model.KeyShares;
import org.miracl.core.BLS12461.FP12;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ECP2;

/**
 * Interface for the crypto module used by the (PESTO) partial IdP.
 * 
 * The implementations may be purely software based or use
 * various hardware augmentations, e.g. Hardware Security Modules,
 * Secure Enclaves, etc. 
 *
 */
public interface ServerCryptoModule extends CommonCrypto {

	/**
	 * Perform a signature on the provided public key, using the provided nonce.
	 * @param publicKey The key to sign.
	 * @param nonce The nonce to use as salt
	 * @return signature 
	 * @throws SignatureException If something went wrong.
	 */
	public byte[] sign(PublicKey publicKey, byte[] nonce, int myId) throws SignatureException;

	/**
	 * Configure the crypto module
	 * @param share The keymaterial
	 * @return true if setup was succesful
	 */
	public boolean setupServer(KeyShares share);

	public byte[] combineSignatures(List<byte[]> partialSignatures) throws SignatureException;

	public FP12 hashAndPair(byte[] bytes, ECP x);

	public FP12 generateBlinding(String ssid, int myId);

	public ECP2 hashToGroup2(byte[] input);

	public byte[] sign(byte[] message) throws SignatureException;
}
