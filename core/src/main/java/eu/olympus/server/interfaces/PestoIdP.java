package eu.olympus.server.interfaces;

import eu.olympus.model.Policy;

public interface PestoIdP extends PestoBasedIdP {
	public String authenticate(String username, byte[] cookie, long salt, byte[] signature, Policy policy) throws Exception;
}
