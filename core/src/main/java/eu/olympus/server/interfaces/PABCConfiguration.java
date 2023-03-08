package eu.olympus.server.interfaces;

import eu.olympus.model.AttributeDefinition;
import java.util.Set;

public interface PABCConfiguration extends PESTOConfiguration {

	public Set<AttributeDefinition> getAttrDefinitions();

	public byte[] getSeed();
	
	public long getLifetime();
	
	public long getAllowedTimeDifference();
	
}
