package eu.olympus.util;

import eu.olympus.model.exceptions.KeyGenerationFailedException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ROM;

/**
 * Interface for the crypto module used by both the
 * (PESTO) client and partial IdP.
 * 
 * The implementations may be purely software based or use
 * various hardware augmentations, e.g. Hardware Security Modules,
 * Secure Enclaves, etc. 
 *
 */
public interface CommonCrypto {

	public static final BigInteger PUBLIC_EXPONENT = new BigInteger("65537");
	// The amount of bits in the OPRF exponent group
	public static final int BITS_IN_GROUP = 461;
	// Curve order of BLS
	public static final BigInteger CURVE_ORDER = Util.BIGToBigInteger(new BIG(ROM.CURVE_Order));
	// The general computational security parameter used for seeds, etc., in bytes
	public static final int COMPUTATION_SEC_BYTES = 16; // = 128 bits
	// The statistical security parameter
	public static final int STATISTICAL_SEC_BYTES = 10; // 80 bits

	/**
	 * Construct a nonce given a username and a salt
	 * @param username The username
	 * @param salt The salt
	 * @return A nonce
	 */
	public byte[] constructNonce(String username, long salt);
	
	/**
	 * Hashes a list of byte arrays.
	 * @param bytes The byte arrays to hash
	 * @return a byte array containing the hash
	 */
	public byte[] hashList(List<byte[]> bytes);

	/**
	 * Hashes a single byte array
	 * @param input The byte array to hash
	 * @return a byte array containing the hash digest
	 */
	public byte[] hashSingleElement(byte[] input);

	/**
	 * Hash a list of inputs to a big integer, uniformly random modulo the modulus
	 * @param input The input to hash
	 * @param modulus The modulo
	 * @return A big integer
	 */
	public BigInteger hashToBigInteger(List<byte[]> input, BigInteger modulus);

	/**
	 * Get a number of random bytes. 
	 * @param noOfBytes The number of bytes to fetch
	 * @return byte array containing the bytes
	 */
	public byte[] getBytes(int noOfBytes);
	
	/**
	 * Produce a RSA public used to validate signatures
	 * of the vIdP
	 * @return A RSA public key.
	 * @throws Exception If the crypto module has not been initialized 
	 */
	public PublicKey getStandardRSAkey() throws KeyGenerationFailedException;
	
	/**
	 * The modulus of the RSA prime used by the vIdP signature scheme
	 * @return
	 */
	public BigInteger getModulus();
	
	/**
	 * Verify a signature of a list of elements
	 * @param publicKey The public key to use for the verification
	 * @param input The list of elements to verify
	 * @param signature The signature
	 * @return true if the verification was successful
	 */
	public boolean verifySignature(PublicKey publicKey, List<byte[]> input, byte[] signature);

	/**
	 * Verify a signature on a byte array message
	 * @param publicKey The public key to use for the verification
	 * @param input The message to verify
	 * @param signature The signature
	 * @return true if the verification was successful
	 */
	public boolean verifySignature(PublicKey publicKey, byte[] input, byte[] signature);

	/**
	 * Produce a random number.
	 * @return The random number
	 */
	public BIG getRandomNumber();

	/**
	 * Hash a byte array to a point on the BLS461 curve (Group 1)
	 * @param input The bytes to hash
	 * @return Element of Group 1 on the BLS461 curve.
	 */
	public ECP hashToGroup1Element(byte[] input);
}
