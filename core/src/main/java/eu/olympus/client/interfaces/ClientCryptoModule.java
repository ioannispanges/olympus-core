package eu.olympus.client.interfaces;

import eu.olympus.model.exceptions.KeyGenerationFailedException;
import eu.olympus.model.exceptions.SigningFailedException;
import eu.olympus.util.CommonCrypto;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;

// Add support for PABC
/**
 * Interface for the crypto module used by the (PESTO) client.
 * 
 * The implementations may be purely software based or use
 * various hardware augmentations, e.g. Hardware Security Modules,
 * Secure Enclaves, etc. 
 *
 */
public interface ClientCryptoModule extends CommonCrypto {

	/**
	 * Transform the input bytes to a public/private keypair.
	 * The PESTO client expects a EC keypair based on the
	 * secp256r1 curve.
	 * @param privateBytes The input bytes
	 * @return A public/private keypair
	 * @throws Exception If the required cryptographic algorithms
	 * are not supported by the system
	 */
	public KeyPair generateKeysFromBytes(byte[] privateBytes) throws KeyGenerationFailedException;
	
	/**
	 * Perform a signature on the provided list of byte arrays.
	 * @param privateKey The key to use for signing.
	 * @param message The byte arrays to sign
	 * @return signature
	 * @throws Exception If the required cryptographic algorithms
	 * are not supported by the system or the key is invalid.
	 */
	public byte[] signECDSA(PrivateKey privateKey, List<byte[]> message) throws SigningFailedException;

	/**
	 * Perform a signature on the provided a single byte array.
	 * @param privateKey The key to use for signing.
	 * @param message The byte array to sign
	 * @return signature
	 * @throws Exception If the required cryptographic algorithms
	 * are not supported by the system or the key is invalid.
	 */
	public byte[] signECDSA(PrivateKey privateKey, byte[] message) throws SigningFailedException;
	/**
	 * Hash a byte array and multiply the result with value r. 
	 * @param r The value to use for multiplication
	 * @param password The byte array to hash
	 * @return A point on the BLS461 curve.
	 */
	public ECP hashAndMultiply(BIG r, byte[] password);
}
