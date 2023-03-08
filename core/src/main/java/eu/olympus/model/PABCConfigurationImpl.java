package eu.olympus.model;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.olympus.server.interfaces.PABCConfiguration;

public class PABCConfigurationImpl extends PESTOConfigurationImpl implements PABCConfiguration{

	private Set<AttributeDefinition> attrDefinitions;
	private byte[] seed;
	private long lifetime;

	public PABCConfigurationImpl() {
		super();
	}

	public PABCConfigurationImpl(int port, int tlsPort, List<String> servers, String keyStorePath,
			String keyStorePassword, String trustStorePath, String trustStorePassword, Certificate cert,
			Map<String, Authorization> tokens, String myToken,
			RSASharedKey rsaSharedKey, Map<Integer, BigInteger> rsaBlindings,
			Map<Integer, BigInteger> oprfBlindings, BigInteger oprfKey, 
			int id, long waitTime, long allowedTimeDifference, long lifetime, byte[] seed,
			Set<AttributeDefinition> attrDefinitions, long sessionLength, String issuerId) {
		super(port, tlsPort, servers, keyStorePath, keyStorePassword, trustStorePath, trustStorePassword, cert, tokens, myToken,
				rsaSharedKey, rsaBlindings, oprfBlindings, oprfKey, id, allowedTimeDifference, waitTime, sessionLength, issuerId);
		this.attrDefinitions = attrDefinitions;
		this.seed = seed;
		this.setLifetime(lifetime);
	}
	
	@Override
	public Set<AttributeDefinition> getAttrDefinitions() {
		return attrDefinitions;
	}
	
	public void setAttrDefinitions(Set<AttributeDefinition> attrDefinitions) {
		this.attrDefinitions = attrDefinitions;
	}

	@Override
	public byte[] getSeed() {
		return seed;
	}

	public void setSeed(byte[] seed) {
		this.seed = seed;
	}

	@Override
	public long getLifetime() {
		return lifetime;
	}

	public void setLifetime(long lifetime) {
		this.lifetime = lifetime;
	}
	
}
