package eu.olympus.server;

import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.PolicyUnfulfilledException;
import eu.olympus.model.Predicate;
import eu.olympus.model.exceptions.TokenGenerationException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.NotSupportedException;
import javax.xml.bind.DatatypeConverter;

import eu.olympus.model.Attribute;
import eu.olympus.model.Operation;
import eu.olympus.model.Policy;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.olympus.server.interfaces.PESTOConfiguration;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.server.interfaces.TokenGenerator;

public class ThresholdOIDCTokenGenerator implements TokenGenerator {
	
	private static Logger logger = LoggerFactory.getLogger(ThresholdOIDCTokenGenerator.class);
	private ServerCryptoModule cryptoModule;
	private PestoDatabase database;
	private int expirationTime = 120;
	private final String issuerId;

	public static byte JWT_PART_SEPARATOR = (byte)46;
	private static List<String> SUPPORTED_CLAIMS = Arrays.asList("name", "given_name", "family_name", "middle_name", "nickname", "birthdate", "email", "email_verified", "gender", "phone_number", "address");
	
	public ThresholdOIDCTokenGenerator(Storage database, ServerCryptoModule cModule, String issuerId) throws IllegalArgumentException {
		if(database instanceof PestoDatabase) {
			this.database = (PestoDatabase) database;
		} else {
			throw new IllegalArgumentException("Not a valid database");
		}		
		this.issuerId = issuerId;
		this.cryptoModule = cModule;
	}

	@Override
	public void setup(PESTOConfiguration configuration) {
		this.expirationTime = (int)(configuration.getSessionLength()/1000);
	}
	
	public String generateOIDCToken(String username, Policy policy, long salt) throws TokenGenerationException {
		try{String header = buildJWTHeader();
			byte[] headerBytes = header.getBytes(Charsets.UTF_8);
			String payload = buildJWTPayload(username, policy, generateId(username, salt));
			byte[] payloadBytes = payload.getBytes(Charset.defaultCharset());
			byte[] toBeSigned = new byte[headerBytes.length+payloadBytes.length+1];
			System.arraycopy(headerBytes, 0, toBeSigned, 0, headerBytes.length);
			toBeSigned[headerBytes.length] = JWT_PART_SEPARATOR;
			System.arraycopy(payloadBytes, 0, toBeSigned, headerBytes.length+1, payloadBytes.length);

			byte[] signature = cryptoModule.sign(toBeSigned);
			return header.concat(".").concat(payload).concat(".").concat(Base64.encodeBase64URLSafeString(signature));
		} catch (Exception e){
			throw new TokenGenerationException("Failed to generate token",e);
		}
	}

	private String generateId(String username, long salt) {
		return Base64.encodeBase64String(cryptoModule.constructNonce(username, salt));
	}
	
	private String generatePseudonym(String username, String aud) {
	    return UUID.nameUUIDFromBytes(cryptoModule.hashList(Arrays.asList(username.getBytes(Charsets.UTF_8), aud.getBytes(Charsets.UTF_8)))).toString();
	}

	private void populateAttributes(JSONObject json, String username, Policy policy) throws PolicyUnfulfilledException, OperationFailedException {
		Map<String, Attribute> attributes = this.database.getAttributes(username);

		for(Predicate predicate : policy.getPredicates()) {
			String key = predicate.getAttributeName().toLowerCase();
			if ("audience".equals(key)) {
				continue;
			}
 			
			// We only support REVEAL operation
			if (predicate.getOperation() != Operation.REVEAL) {
				logger.warn("Policy "+policy.getPolicyId()+ " contained REVEAL operation for "+predicate.getAttributeName()+ " and request was dropped");
				throw new PolicyUnfulfilledException("Operation: "+predicate.getOperation()+ " is not supported");
			}
			Attribute attribute = attributes.get(key);
			if(attribute == null) {
				logger.warn("Policy "+policy.getPolicyId()+ " requires attribute "+key+ ", which the user does not have and request was dropped");
				throw new PolicyUnfulfilledException("User does not have the \"" + key + "\" attribute");
			}
			if(checkStandardClaim(predicate.getAttributeName().toLowerCase())) {
				json.put(predicate.getAttributeName(), attribute);
			} else {
				logger.warn("Policy "+policy.getPolicyId()+ " requires attribute "+key+ ", which is not a support OIDC claim");
				throw new PolicyUnfulfilledException(predicate.getAttributeName()+" is not a supported OIDC standard claim");
			}
		}
	}
	
	private boolean checkStandardClaim(String attributeName) {
		return SUPPORTED_CLAIMS.contains(attributeName);
	}

	private String buildJWTPayload(String username, Policy policy, String id) throws PolicyUnfulfilledException, OperationFailedException {
		JSONObject json = new JSONObject();
		String audience = getAudience(policy);
		json.put("iss", issuerId); 
		// identifier for authenticated user
		json.put("sub", generatePseudonym(username, audience)); 
		// intended receiver of token (ie. the service provider)
		json.put("aud", audience); 
		// issuance time eg. 1550833207
		json.put("iat", (System.currentTimeMillis()/1000));
		// expiration time eg. 1550833207
		json.put("exp", (System.currentTimeMillis()/1000)+expirationTime);
		populateAttributes(json, username, policy);
		// when was user last logged in without sso. This is required if a 'max-age' request is made. We always include it
		json.put("auth_time", (System.currentTimeMillis()/1000)); 
		// unique token id. constructed from username+nonce 
		json.put("jti", id);
		// optional nonce from the policy / request
		if(policy.getPolicyId() != null) {
			json.put("nonce", policy.getPolicyId()); 
		}

		// TODO "Access_token" is not supported in OLYMPUS, atleast it does not make
		// sense, as it is used for a SP to contact an IdP with the intent of getting user information
		// from the /userinfo endpoint. Since we do not intend on having the SP contact the IdP, this functionality is not implemented.
		// Should we need to implement the "access_token", perhaps we can let the client
		// create a value in the policy and have the vIdP sign the hash that way.
		// This does require the SP to contact the client for the "/userinfo" lookup (the functionality
		// can be implemented using getAllAttributes), which is ok from a linkability pov, but might not
		// be possible in practice. The policy provided access token, could also be added as a session cookie
		// on the vIdP, granting access to that users information.


		//	json.put("at_hash", generate_at_hash(accessToken)); //a hash of the access token

		//json.put("acr", "PESTO"); //authentication method - must match "act_value" parameter from policy -if we support it -- OPTIONAL
		return Base64.encodeBase64URLSafeString(json.toString().getBytes(Charsets.UTF_8));
	}

	private String getAudience(Policy policy) throws PolicyUnfulfilledException {
		for(Predicate predicate: policy.getPredicates()) {
			if ("audience".contentEquals(predicate.getAttributeName().toLowerCase()) ) {
				return predicate.getValue().toString();
			}
		}
		logger.warn("Policy "+policy.getPolicyId()+ " does not contains an audience");
		throw new PolicyUnfulfilledException("Policy does not contain an audience");
	}

	private String buildJWTHeader() {
		JSONObject json = new JSONObject();
		json.put("alg", "RS256");
		
		try {
			String fingerPrint = DatatypeConverter.printHexBinary(
					MessageDigest.getInstance("SHA-1").digest(this.getPublicKey().getEncoded()));
			json.put("x5t", fingerPrint); //fingerprint of the used cert (SHA1 hash)
		} catch (NoSuchAlgorithmException e) {
			logger.error("Failed to compute x5t header value.",e);
		}

		// I expect predistributed certificates is the way to go, to avoid the SP
		// looking up keys (causing potential linking). 
		// Alternatively we can use kid and implement a jwks endpoint:
		// json.put("kid", "-38074812"); //Key id of key found on jwks endpoint of issuers

		return Base64.encodeBase64URLSafeString(json.toString().getBytes(Charsets.UTF_8));
	}

	@Override
	public PublicKey getPublicKey() {
		try {
			return cryptoModule.getStandardRSAkey();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String generateToken(Map<String, Attribute> assertions) throws NotSupportedException {
		throw new NotSupportedException("not supported for OIDC token generator");
	}
}
