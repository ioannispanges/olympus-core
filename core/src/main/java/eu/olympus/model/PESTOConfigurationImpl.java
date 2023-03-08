package eu.olympus.model;

import java.math.BigInteger;

import eu.olympus.server.interfaces.PESTOConfiguration;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PESTOConfigurationImpl extends ServerConfigurationImpl implements PESTOConfiguration{

	private RSASharedKey keyMaterial;
	@JsonProperty("rsaBlindings")
	private Map<Integer, BigInteger> rsaBlindings;
	private BigInteger oprfKey;
	@JsonProperty("oprfBlindings")
	private Map<Integer, BigInteger> oprfBlinding;
	@JsonProperty("remoteShares")
	private Map<Integer, byte[]> remoteShares;
	private byte[] localKeyShare;
	private int id;
	/** The amount of time, in miliseconds, we allow the user's salt to be off by compared to the
	 *	current time. This is required to avoid someone doing a denial of service attack of a user by
	 *	hammering the DB with time stamps far in the future.
	 */
	private long allowedTimeDiff = 10000;
	private long waitTime = 1000;
	private long sessionLength = 60000l;

	public PESTOConfigurationImpl() {

	}

	public PESTOConfigurationImpl(int port, int tlsPort, List<String> servers, String keyStorePath,
			String keyStorePassword, String trustStorePath, String trustStorePassword, Certificate cert,
			Map<String, Authorization> tokens, String myToken,
			RSASharedKey keyMaterial, Map<Integer, BigInteger> rsaBlindings,
			Map<Integer, BigInteger> oprfBlindings, BigInteger oprfKey,
			int id, long allowedTimeDiff, long waitTime, long sessionLength, String issuerId) {
		super(port, tlsPort, servers, keyStorePath, keyStorePassword, trustStorePath, trustStorePassword, cert, tokens, myToken, issuerId);
		this.keyMaterial = keyMaterial;
		this.rsaBlindings = rsaBlindings;
		this.oprfBlinding = oprfBlindings;
		this.oprfKey = oprfKey;
		this.id = id;
		this.allowedTimeDiff = allowedTimeDiff;
		this.waitTime = waitTime;
		this.sessionLength = sessionLength;
	}

	@Override
	public RSASharedKey getKeyMaterial() {
		return keyMaterial;
	}

	public void setKeyMaterial(RSASharedKey keyMaterial) {
		this.keyMaterial = keyMaterial;
	}

	@Override
	public Map<Integer, BigInteger> getRsaBlindings() {
		return rsaBlindings;
	}

	public void setRsaBlindings(Map<Integer, BigInteger> rsaBlindings) {
		this.rsaBlindings = rsaBlindings;
	}

	@Override
	public Map<Integer, BigInteger> getOprfBlindings() {
		return oprfBlinding;
	}

	public void setOprfBlindings(Map<Integer, BigInteger> oprfBlindings) {
		this.oprfBlinding = oprfBlindings;
	}

	@Override
	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	@Override
	public long getAllowedTimeDifference() {
		return allowedTimeDiff;
	}

	public void setAllowedTimeDifference(long allowedTimeDiff) {
		this.allowedTimeDiff = allowedTimeDiff;
	}

	@Override
	public BigInteger getOprfKey() {
		return oprfKey;
	}
	
	public void setOprfKey(BigInteger oprfKey) {
		this.oprfKey = oprfKey;
	}

	public void setWaitTime(long waitTime) {
		this.waitTime = waitTime;
	}

	@Override
	public long getWaitTime() {
		return this.waitTime;
	}

	@Override
	public byte[] getLocalKeyShare() {
		return localKeyShare;
	}

	public void setLocalKeyShare(byte[] localKeyShare) {
		this.localKeyShare = localKeyShare;
	}
	
	@Override	
	public Map<Integer, byte[]> getRemoteShares() {
		return remoteShares;
	}

	public void setRemoteShares(Map<Integer, byte[]> remoteShares) {
		this.remoteShares = remoteShares;
	}

	@Override
	public long getSessionLength() {
		return this.sessionLength;
	}
	
	public void setSessionLength(long sessionLength) {
		this.sessionLength = sessionLength;
	}

}
