package eu.olympus.util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Performs "advanced" RSA signatures of PASTA.
 * Allows us to use any BigInt as privatekey,
 * useful when doing distributed RSA.
 *
 */
public class RSASignatureUtil {

	public static byte JWT_PART_SEPARATOR = (byte)46;
	private static final byte[] SHA256    = new byte[]{(byte)0x30, (byte)0x31,
			(byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x60,
			(byte)0x86, (byte)0x48,	(byte)0x01, (byte)0x65, (byte)0x03,
			(byte)0x04, (byte)0x02, (byte)0x01, (byte)0x05, (byte)0x00,
			(byte)0x04, (byte)0x20};

	private RSASignatureUtil() {}

	public static byte[] signWithBlinding(byte[] toBeSigned, BigInteger modulus,
			BigInteger privateKey, Map<Integer, BigInteger> blindingKeys, int myId,
			byte[] salt) throws SignatureException {
		int emLen = modulus.bitLength()/8;
		
		if((modulus.bitLength()%8) != 0) {
			emLen++;
		}
		
		byte[] em = emsaEncode(toBeSigned, emLen); //Step 1 
		BigInteger m = new BigInteger(em); //Step 2
		
		BigInteger h = BigInteger.ONE;
		for(int i : blindingKeys.keySet()) {
			BigInteger c = SoftwareCommonCrypto
					.hashToBigIntegerSha512(Arrays.asList(blindingKeys.get(i).toByteArray(), salt), modulus);
			if(i > myId) {
				c = c.modInverse(modulus);
			}
			h = h.multiply(c).mod(modulus);
		}

		BigInteger pk = privateKey;//.add(dMark);
		BigInteger s = m.modPow(pk, modulus); //Step 3
		s = s.multiply(h).mod(modulus);
		
		byte[] signature = s.toByteArray();// Step 4
		
		if(signature.length > emLen) {
			byte[] newSig = new byte[signature.length-1];
			System.arraycopy(signature, 1, newSig, 0, signature.length-1);
			signature = newSig;
		}

		return signature;
		
	}
	
	public static byte[] sign(byte[] toBeSigned, BigInteger modulus,
			BigInteger privateKey) throws SignatureException {
		int emLen = modulus.bitLength()/8;
		if((modulus.bitLength()%8) != 0) {
			emLen++;
		}
		
		byte[] em = emsaEncode(toBeSigned, emLen); //Step 1 
		BigInteger m = new BigInteger(em); //Step 2

		BigInteger s = m.modPow(privateKey, modulus); //Step 3
				
		byte[] signature = s.toByteArray();// Step 4
		
		if(signature.length > emLen) {
			byte[] newSig = new byte[signature.length-1];
			System.arraycopy(signature, 1, newSig, 0, signature.length-1);
			signature = newSig;
		}
		return signature;
	}

	private static byte[] emsaEncode(byte[] message, int emLen) throws SignatureException {
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			sha.update(message);
			byte[] hash = sha.digest();
			byte[] dInfo = new byte[hash.length+SHA256.length];
			System.arraycopy(SHA256, 0, dInfo, 0, SHA256.length);
			System.arraycopy(hash, 0, dInfo, SHA256.length, hash.length);

			int tLen = dInfo.length;
			byte[] ps = new byte[emLen-tLen-3];
			for(int i = 0; i< ps.length; i++) {
				ps[i] = (byte)0xff;
			}
			byte[] em = new byte[emLen];
			em[0] = (byte)0x00;
			em[1] = (byte)0x01;
			System.arraycopy(ps, 0, em, 2, ps.length);
			em[ps.length+2] = (byte)0x00;
			System.arraycopy(dInfo, 0, em, ps.length+3, tLen);
			return em;
		} catch (NoSuchAlgorithmException e){
			throw new SignatureException("Failed to encode message", e);
		}

	}

	
	
	public static byte[] combineSignatures(List<byte[]> partialSignatures, BigInteger modulus) {
		BigInteger product = BigInteger.ONE;
		for(byte[] bytes: partialSignatures) {
			byte[] sig = new byte[bytes.length+1];
			System.arraycopy(bytes, 0, sig, 1, bytes.length);
			BigInteger s1 = new BigInteger(sig).mod(modulus);
			
			product = (product.multiply(s1)).mod(modulus);
		}

		int emLen = modulus.bitLength()/8;
		
		if((modulus.bitLength()%8) != 0) {
			emLen++;
		}
		
		byte[] signatureCombined = product.toByteArray();// Step 4
		
		if(signatureCombined.length > emLen) {
			byte[] newSig = new byte[emLen];
			// Remove potential 0-prefix
			System.arraycopy(signatureCombined, signatureCombined.length - emLen, newSig, 0, signatureCombined.length-1);
			signatureCombined = newSig;
		} else if (signatureCombined.length < emLen) {
			byte[] newSig = new byte[emLen];
			// Pad with a 0-prefix if the result is too short
			System.arraycopy(signatureCombined, 0, newSig, emLen - signatureCombined.length, signatureCombined.length);
			signatureCombined = newSig;
		}
		return signatureCombined;
	}
}
