package eu.olympus.server.interfaces;

import eu.olympus.model.Authorization;

public interface UserAuthorizationDatabase {
	public Authorization lookupCookie(String cookie);

	public void deleteCookie(String cookie);

	public void storeCookie(String cookie, Authorization user);
}
