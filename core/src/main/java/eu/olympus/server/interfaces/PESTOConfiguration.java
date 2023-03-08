package eu.olympus.server.interfaces;

import java.math.BigInteger;

import eu.olympus.model.RSASharedKey;
import java.util.Map;

public interface PESTOConfiguration extends ServerConfiguration {
	
	public RSASharedKey getKeyMaterial();

	public Map<Integer, BigInteger> getRsaBlindings();

	public Map<Integer, BigInteger> getOprfBlindings();

	public int getId();
	
	/** The amount of time, in miliseconds, we allow the user's salt to be off by compared to the
	 *	current time. This is required to avoid someone doing a denial of service attack of a user by
	 *	hammering the DB with time stamps far in the future.
	 */
	public long getAllowedTimeDifference();
	
	public BigInteger getOprfKey();
	
	public long getWaitTime();

	public Map<Integer, byte[]> getRemoteShares();

	public byte[] getLocalKeyShare();
	
	public long getSessionLength();
}
