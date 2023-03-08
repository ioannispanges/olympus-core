package eu.olympus.model;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for representing data belonging to a PESTO user.
 * The contained data is:
 * -a salt used for generating nonces in the OPRF protocol
 * -the public part of the key pair derived from the OPRF protocol
 * -a key-value mapping of the attributes of the user
 *
 */
public class UserData {

	private long salt;
	private final Map<String, Attribute> attributes = new HashMap<>();
	private final Map<String, MFAInformation> secondFactorInformation = new HashMap<>();
	private final PublicKey publicKey;

	public UserData(PublicKey publicKey, long salt) {
		this.publicKey = publicKey;
		this.salt = salt;
	}

	public long getSalt() {
		return salt;
	}

	public void setSalt(long salt) {
		this.salt = salt;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public Map<String, Attribute> getAttributes() {
		return this.attributes;
	}

	public Object putAttribute(String key, Attribute value) {
		return attributes.put(key, value);
	}

	public void putAllAttributes(Map<String, Attribute> attributes) {
		this.attributes.putAll(attributes);
	}
	
	public Map<String, MFAInformation> getSecondFactors() {
		return this.secondFactorInformation;
	}

	public void putSecondFactor(String key, MFAInformation value) {
		secondFactorInformation.put(key, value);
	}
}
