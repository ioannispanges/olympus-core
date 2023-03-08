package eu.olympus.util;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.List;

import org.apache.commons.codec.binary.Base64;

/**
 * Utility class related to handling JSON Web Tokens.
 * 
 *
 */
public class JWTUtil {

	private static byte JWT_PART_SEPARATOR = (byte)46;
	
	private JWTUtil() {}
	
 	public static String combineTokens(List<String> tokens, BigInteger modulus) {
 		if((modulus.bitLength()%8) != 0) {
			throw new IllegalArgumentException("Modulus bitlength must be a multiple of 8.");
		}
 		if(tokens.size()==1) {
			return tokens.get(0);
		}
		String[] split = tokens.get(0).split("\\.");
		byte[] headerBytes = split[0].getBytes(Charset.defaultCharset());//Should be UTF-8
		byte[] payloadBytes = split[1].getBytes(Charset.defaultCharset());
		byte[] toBeSigned = new byte[headerBytes.length+payloadBytes.length+1];
		System.arraycopy(headerBytes, 0, toBeSigned, 0, headerBytes.length);
		toBeSigned[headerBytes.length] = JWT_PART_SEPARATOR;
		System.arraycopy(payloadBytes, 0, toBeSigned, headerBytes.length+1, payloadBytes.length);

		int emLen = modulus.bitLength()/8;
		
		
		BigInteger[] signatures = new BigInteger[tokens.size()];
		int i = 0;
		for(String s: tokens) {
			String sig = s.substring(s.lastIndexOf("."));
			
			byte[] bytes = Base64.decodeBase64(sig);
			byte[] b2 = new byte[bytes.length+1];
			System.arraycopy(bytes, 0, b2, 1, bytes.length);
			signatures[i] = new BigInteger(b2);
			i++;
		}
		BigInteger product = signatures[0];
		for(i = 1; i<tokens.size(); i++) {
			product = (product.multiply(signatures[i])).mod(modulus);
		}

		byte[] signature = product.toByteArray();// Step 4
		if(signature.length > emLen) {
			byte[] newSig = new byte[signature.length-1];
			System.arraycopy(signature, 1, newSig, 0, signature.length-1);
			signature = newSig;
		}
		return tokens.get(0).substring(0,tokens.get(0).lastIndexOf(".")+1).concat(Base64.encodeBase64URLSafeString(signature));
	}
	
}
