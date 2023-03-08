package eu.olympus.util;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.Authorization;
import eu.olympus.model.KeyShares;
import eu.olympus.model.PABCConfigurationImpl;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.PestoRefresher;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.rest.Role;
import eu.olympus.util.keyManagement.CertificateUtil;
import eu.olympus.util.keyManagement.SecureStoreUtil;

public abstract class ConfigurationUtil {

	protected String outputPath;
	protected KeyStore[] keystores;
	protected String[] servers;
	protected String[] keyStorePaths;
	protected String[] keyStorePasswords;
	protected String[] trustStorePaths; 
	protected String trustStorePassword; 
	protected int[] portNumbers;
	protected int[] tlsPortNumbers;
	protected String issuerId;
	protected String RDN;
	protected String[] TLS_RDN;
	protected String[] certNames;
	protected String[] keyNames;
	protected String[][] SAN;
	protected Set<AttributeDefinition> attrDefinitions;
	protected RSAPrivateCrtKey sk;
	protected int TLS_KEYSIZE;
	
	protected long waitTime;
	protected long allowedTimeDifference;
	protected long lifetime;
	protected long sessionLength;
	
	protected KeyStore trustStore;
	protected PABCConfigurationImpl[] configurations;
	protected Random rng;
	
	protected void generateConfigurations() throws Exception {
		int amount = servers.length;
		configurations = new PABCConfigurationImpl[amount];

		keystores = new KeyStore[amount];
		for(int i = 0; i< amount; i++) {
			keystores[i] = SecureStoreUtil.getEmptySecurityStore();
		}
		
		byte[][] seed = new byte[amount][];
		Map<String, Authorization>[] tokens = new Map[amount];
		String[] myToken = new String[amount];
		for(int i =0; i< amount; i++) {
			seed[i] = new byte[64];
			rng.nextBytes(seed[i]);

			tokens[i] = new HashMap<>();
			byte[] buffer = new byte[64];
			rng.nextBytes(buffer);
			tokens[i].put(Base64.encodeBase64String(buffer), new Authorization("Admin", Arrays.asList(Role.ADMIN), System.currentTimeMillis()+604800000));
			rng.nextBytes(buffer);
			myToken[i] = Base64.encodeBase64String(buffer);
		}
		for(int i = 0; i< amount; i++) {
			for(int j = 0; j< amount; j++) {
				if(j!=i) {
					tokens[i].put(myToken[j], new Authorization("Server-"+j, Arrays.asList(Role.SERVER), System.currentTimeMillis()+604800000));
				}
			}
		}
				
		RSASharedKey[] rsaSharedKeys = new RSASharedKey[amount];
		Map<Integer, BigInteger>[] rsaBlindings = new Map[amount];
		Map<Integer, BigInteger>[]  oprfBlindings = new Map[amount];
		Map<Integer, byte[]>[] remoteKeyShares = new Map[amount];
		BigInteger[] oprfKeys = new BigInteger[amount];
		byte[][] localKeyShares = new byte[amount][]; 

		Certificate certificate = doKeyShares(sk, amount, rng, 
				rsaSharedKeys, rsaBlindings, oprfBlindings, oprfKeys, 
				localKeyShares, remoteKeyShares, RDN);

		for(int i = 0; i< amount; i++) {
			ArrayList<String> otherServers = new ArrayList<String>();
			for(int j = 0; j< amount; j++) {
				if(j != i) {
					otherServers.add(servers[j]);
				}
			}
			configurations[i] = new PABCConfigurationImpl(portNumbers[i], tlsPortNumbers[i], otherServers,
					keyStorePaths[i], keyStorePasswords[i], trustStorePaths[i], trustStorePassword, certificate, 
					tokens[i], myToken[i], 
					rsaSharedKeys[i], rsaBlindings[i], oprfBlindings[i], oprfKeys[i], i, 
					waitTime, allowedTimeDifference, lifetime, 
					seed[i], attrDefinitions, sessionLength, issuerId);
			configurations[i].setLocalKeyShare(localKeyShares[i]);
			configurations[i].setRemoteShares(remoteKeyShares[i]);

			generateKeyAndTrustStore();
		}
	}
	
	private void generateKeyAndTrustStore() throws Exception {
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

		generator.initialize(TLS_KEYSIZE, random);
		trustStore = SecureStoreUtil.getEmptySecurityStore();
		for(int i = 0; i< keystores.length; i++) {
			KeyPair pair = generator.generateKeyPair();
			PKCS10CertificationRequest csr = CertificateUtil.makeCSR((RSAPrivateKey)pair.getPrivate(), (RSAPublicKey)pair.getPublic(), TLS_RDN[i], SAN[i]);
			Certificate cert = CertificateUtil.makeSelfSignedCert((RSAPrivateKey) pair.getPrivate(), csr);
			keystores[i].setKeyEntry(keyNames[i], pair.getPrivate(), keyStorePasswords[i].toCharArray(), new Certificate[] {cert});			
			keystores[i].setCertificateEntry(certNames[i], cert);
			trustStore.setCertificateEntry("server-"+i+"-certificate", cert);
		}
	}

	protected Certificate doKeyShares(RSAPrivateCrtKey sk, int amount, Random rnd, 
			RSASharedKey[] rsaSharedKeys, Map<Integer, BigInteger>[] rsaBlindings, Map<Integer, BigInteger>[] oprfBlindings, 
			BigInteger[] oprfKeys, byte[][] localKeyShares, Map<Integer, byte[]>[] remoteKeyShares, String RDN) throws Exception {
		
		BigInteger d = sk.getPrivateExponent();
		
		List<BigInteger> rsaShares = new ArrayList<>(amount);
		BigInteger sum = BigInteger.ZERO;
		for(int i=0; i< amount-1; i++) {
			BigInteger currentRSAShare = new BigInteger(sk.getModulus().bitLength()+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(sk.getModulus());
			sum = sum.add(currentRSAShare);
			rsaShares.add(currentRSAShare);
			oprfKeys[i] = new BigInteger(CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(CommonCrypto.CURVE_ORDER);
		}
		rsaShares.add(d.subtract(sum));
		oprfKeys[amount-1] = new BigInteger(CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(CommonCrypto.CURVE_ORDER);

		for(int i=0; i< amount; i++) {
			rsaSharedKeys[i] = new RSASharedKey(sk.getModulus(), rsaShares.get(i), sk.getPublicExponent());
			rsaBlindings[i] = new HashMap<>(amount);
			oprfBlindings[i] = new HashMap<>(amount);
			remoteKeyShares[i] = new HashMap<>(amount);
 		}
		for(int i=0; i< amount; i++) {
			for(int j = i; j<amount; j++) {
				if(i != j) {
					BigInteger current = new BigInteger(CommonCrypto.COMPUTATION_SEC_BYTES * 8, rnd);
					rsaBlindings[i].put(j, current);
					rsaBlindings[j].put(i, current);
					current = new BigInteger(CommonCrypto.COMPUTATION_SEC_BYTES * 8, rnd);
					oprfBlindings[i].put(j, current);
					oprfBlindings[j].put(i, current);
				}
			}
		}

		for(int i = 0; i< amount; i++) {
			PestoRefresher refresher = new PestoRefresher(i, new SoftwareServerCryptoModule(new Random(i)));
			KeyShares share = new KeyShares(rsaSharedKeys[i], rsaBlindings[i], oprfKeys[i], oprfBlindings[i]);
			List<byte[]> shares = refresher.reshareMasterKeys(share, amount);
			localKeyShares[i] = shares.remove(0);
			for(int j = 0; j < amount; j++) {
				if(i != j) {
					remoteKeyShares[j].put(i, shares.remove(0));
				}
			}
		}

		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(sk.getModulus(), sk.getPublicExponent());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(publicKeySpec);
		
		PKCS10CertificationRequest csr2 = CertificateUtil
				.makeCSR(sk, publicKey, RDN, null);

		return CertificateUtil.makeSelfSignedCert(sk, csr2);
	}
}
