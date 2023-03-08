/*
 * inspiration from 
 * https://www.javacodegeeks.com/2016/12/adding-microbenchmarking-build-process.html
 * and
 * https://www.mkyong.com/java/java-jmh-benchmark-tutorial/
 */

package eu.olympus.benchmark;

import eu.olympus.client.PestoClient;
import eu.olympus.client.PestoIdPRESTConnection;
import eu.olympus.client.SoftwareClientCryptoModule;
import eu.olympus.client.interfaces.ClientCryptoModule;
import eu.olympus.client.interfaces.UserClient;
import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import eu.olympus.model.Predicate;
import eu.olympus.util.CommonCrypto;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;
import javax.net.ssl.HostnameVerifier;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;

public class Benchmark {
	
	
	private static final int ITERATIONS = 30;
	private static final int WARMUP = 30;
	
	private static String user = "username";
	private static String password = "password";
	private static UserClient client;

	public static void main(String[] args) throws Exception {
		user = UUID.randomUUID().toString();
		List<String> servIPs = new ArrayList<String>(2);
		servIPs.add(args[0]);
		servIPs.add(args[1]);
		servIPs.add(args[2]);
		List<PestoIdPRESTConnection> idps = new ArrayList<PestoIdPRESTConnection>();
		for (int i = 0; i < servIPs.size(); i++) {
			System.out.println("Server " + (i + 1) + ": " + servIPs.get(i));
			PestoIdPRESTConnection idp = new PestoIdPRESTConnection(servIPs.get(i), "", i, 100000);
			idps.add(idp);
		}

		Properties systemProps = System.getProperties();
		systemProps.put("javax.net.ssl.trustStore", "core/src/test/resources/truststore.jks");
		systemProps.put("javax.net.ssl.trustStorePassword", "OLYMPUS");
		// Ensure that there is a certificate in the trust store for the webserver connecting
		HostnameVerifier verifier = new DefaultHostnameVerifier();
		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(verifier);

		setup(servIPs, idps);

		List<Long> times;
		System.out.println("Executing " + ITERATIONS + " time each with " + WARMUP + " warmups");
		//
		times = benchmarkCreateUser();
		System.out.println("Create user average time is " + avg(times) + "ms with std " + std(times));
		//
		times = benchmarkAuthenticate();
		System.out.println("Authenticate average time is " + avg(times) + "ms with std " + std(times));
	}

	private static void setup(List<String> servIps, List<PestoIdPRESTConnection> idps) throws Exception {
		int serverCount = servIps.size();
		long startTime = System.currentTimeMillis();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		RSAPrivateCrtKey pk = (RSAPrivateCrtKey)pair.getPrivate();
		BigInteger d = pk.getPrivateExponent();

		Random rnd = new SecureRandom();
		BigInteger[] keyShares = new BigInteger[serverCount];
		BigInteger sum = BigInteger.ZERO;

		for(int i=0; i< serverCount-1; i++) {
			keyShares[i]= new BigInteger(pk.getModulus().bitLength()+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(pk.getModulus());
			sum = sum.add(keyShares[i]);
		}
		
		keyShares[serverCount-1] = d.subtract(sum);

		byte[] authKey = new byte[] {0x42};
		BigInteger[] oprfKeys = new BigInteger[serverCount];
		List<Map<Integer, BigInteger>> rsaBlindings = new ArrayList<Map<Integer, BigInteger>>(serverCount);
		List<Map<Integer, BigInteger>> oprfBlindings = new ArrayList<Map<Integer, BigInteger>>(serverCount);
		for(int i=0; i< serverCount; i++) {
			rsaBlindings.add(new HashMap<>(serverCount));
			oprfBlindings.add(new HashMap<>(serverCount));
			oprfKeys[i] = new BigInteger(CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(CommonCrypto.CURVE_ORDER);
		}
		for(int i=0; i< serverCount; i++) {
			for(int j = i; j<serverCount; j++) {
				if(i != j) {
					BigInteger current = new BigInteger(pk.getModulus().bitLength()+8*CommonCrypto.STATISTICAL_SEC_BYTES, rnd).mod(pk.getModulus());;
					rsaBlindings.get(i).put(j, current);
					rsaBlindings.get(j).put(i, current);
					current = new BigInteger(CommonCrypto.COMPUTATION_SEC_BYTES * 8, rnd);
					oprfBlindings.get(i).put(j, current);
					oprfBlindings.get(j).put(i, current);
				}
			}
		}

		javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
				new javax.net.ssl.HostnameVerifier(){

					public boolean verify(String hostname,
							javax.net.ssl.SSLSession sslSession) {
						//return hostname.equals("localhost");
						return true;
					}
				});
		System.out.println("creating connections");

		ClientCryptoModule crypto = new SoftwareClientCryptoModule(new SecureRandom(), ((RSAPublicKey) idps.get(0).getCertificate().getPublicKey()).getModulus());
		client = new PestoClient(idps, crypto);
		
		System.out.println("setup took "+(System.currentTimeMillis()-startTime)+" ms");
	}

	 private static double avg(List<Long> times) {
		 double sum = 0;
		 for (int i = 0; i < times.size(); i++) {
			 sum += times.get(i).doubleValue();
		}
		 return sum/times.size();
	}

	private static double std(List<Long> times) {
		double avg = avg(times);
		double squaredDiff = 0.0;
		for (int i = 0; i < times.size(); i++) {
			squaredDiff += (avg - times.get(i).doubleValue()) * (avg - times.get(i).doubleValue());
		}
		return Math.sqrt(squaredDiff/times.size());
	}
	 
	 private static List<Long> benchmarkCreateUser() throws Exception{

			List<Long> times = new ArrayList<>(ITERATIONS);
			long startTime = 0;
			long endTime = 0;
			for (int i = 0; i < ITERATIONS + WARMUP; i++) {
				startTime = java.lang.System.currentTimeMillis();
				client.createUser(user+i, password);
				endTime = java.lang.System.currentTimeMillis();
				Thread.sleep(20);
				if(i >= WARMUP){
					times.add(endTime - startTime);
				}
			}
			return times;
	 }
	 
	 private static List<Long> benchmarkAuthenticate() throws Exception{
		 List<Long> times = new ArrayList<>(ITERATIONS);

		 long startTime = 0;
		 long endTime = 0;

		 Policy policy = new Policy();
		 List<Predicate> predicates = new ArrayList<>();;
		 predicates.add(new Predicate("audience", Operation.REVEAL, new Attribute("test-service-provider")));
		 policy.setPredicates(predicates);
		 policy.setPolicyId("ThePolicyId");

		 for (int i = 0; i < ITERATIONS + WARMUP; i++) {
			 startTime = java.lang.System.currentTimeMillis();
			 client.authenticate(user+i, password, policy, null, "NONE");
			 endTime = java.lang.System.currentTimeMillis();
			 Thread.sleep(20);
			 if(i >= WARMUP){
				 times.add(endTime - startTime);
			 }
		}
		 return times;
	 }
}
