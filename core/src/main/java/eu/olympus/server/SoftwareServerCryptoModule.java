package eu.olympus.server;

import eu.olympus.model.KeyShares;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.util.CommonCrypto;
import eu.olympus.util.KeySerializer;
import eu.olympus.util.RSASignatureUtil;
import eu.olympus.util.SoftwareCommonCrypto;
import eu.olympus.util.Util;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.Charsets;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.BLS;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.ECP2;
import org.miracl.core.BLS12461.FP;
import org.miracl.core.BLS12461.FP12;
import org.miracl.core.BLS12461.FP2;
import org.miracl.core.BLS12461.PAIR;
import org.miracl.core.BLS12461.ROM;
import org.miracl.core.HMAC;

public class SoftwareServerCryptoModule extends SoftwareCommonCrypto implements ServerCryptoModule {

	private BigInteger modulus;
	private BigInteger privateKey;
	private Map<Integer, BigInteger> rsaBlindings;
	private Map<Integer, BigInteger> oprfBlindings;
	private final FP12 generator =
			PAIR.fexp(PAIR.ate(ECP2.generator(),
			ECP.generator()));
	private BIG oprfKey;
	
	public SoftwareServerCryptoModule(Random random) {
		super(random);
	}

	@Override
	public boolean setupServer(KeyShares share) {
		try {
			this.modulus = share.getRsaShare().getModulus();
			this.privateKey = share.getRsaShare().getPrivateKey();
			this.oprfKey = Util.BigIntegerToBIG(share.getOprfKey());
			this.rsaBlindings = share.getRsaBlindings();
			this.oprfBlindings = share.getOprfBlindings();
			return true;
		} catch(Exception e) {
			return false;
		}
	}
	
	@Override
	public byte[] sign(PublicKey publicKey, byte[] input, int myId) throws SignatureException {
		byte[] serverSignature = RSASignatureUtil
				.signWithBlinding(KeySerializer.serialize(publicKey).getBytes(), modulus, privateKey, rsaBlindings, myId, input);
		return serverSignature;
	}

	@Override
	public byte[] sign(byte[] message) throws SignatureException{
		byte[] signature = RSASignatureUtil.sign(message, modulus, privateKey);
		return signature;
	}

	private BIG hashToBIG(byte[] input, String ssid) {
		byte[] bytes = hashList(Arrays.asList(input, ssid.getBytes(StandardCharsets.UTF_8)));
		return BIG.fromBytes(bytes);
	}

	@Override
	public byte[] combineSignatures(List<byte[]> partialSignatures) {
		byte[] combinedSignature = RSASignatureUtil
				.combineSignatures(partialSignatures, modulus);
		return combinedSignature;
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public FP12 hashAndPair(byte[] input, ECP x) {
		ECP2 t = hashToGroup2(input).mul(oprfKey);
		FP12 y = PAIR.fexp(PAIR.ate(t, x));
		return y;
	}

	@Override
	public FP12 generateBlinding(String ssid, int myId) {
		FP12 product = new FP12();
		product.one();
		for(int i : oprfBlindings.keySet()) {
			if(i != (myId)) { //skip s_(i,i)
				BIG value = hashToBIG(oprfBlindings.get(i).toByteArray(), ssid);
				FP12 val = generator.pow(value);
				if(i< myId) {
					val.inverse();						
				}
				product.mul(val);
			}
		}
		return product;
	}

	// Implements secure and constant time hashing to curve
	// Based on BLS.bls_hash_to_point
	@Override
	public ECP2 hashToGroup2(byte[] input) {
		FP realA = hashToFP(input, "real-a");
		FP imaginaryA = hashToFP(input, "imaginary-a");
		FP2 fpA = new FP2(realA, imaginaryA);
		FP realB = hashToFP(input, "real-b");
		FP imaginaryB = hashToFP(input, "imaginary-b");
		FP2 fpB = new FP2(realB, imaginaryB);
		ECP2 PA = ECP2.map2point(fpA);
		ECP2 PB = ECP2.map2point(fpB);
		PA.add(PB);
		PA.cfp();
		PA.affine();
		return PA;
	}

	private FP hashToFP(byte[] input, String salt) {
		// Use PBKDF2 to prevent potential issues with extension attacks given SHA2 is used with 2 iterations, hashing to BLS.BFS bytes
		byte[] hash = HMAC.PBKDF2(HMAC.MC_SHA2, 32, input, salt.getBytes(Charsets.UTF_8), 2, BLS.BFS+CommonCrypto.STATISTICAL_SEC_BYTES);
		BIG res = BIG.fromBytes(hash);
		// Note that technically the digest should be used as input to a universal hash function hashing exactly to the field size
		res.mod(new BIG(ROM.Modulus));
		return new FP(res);
	}
}
