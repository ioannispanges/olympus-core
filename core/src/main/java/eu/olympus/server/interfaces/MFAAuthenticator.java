package eu.olympus.server.interfaces;

import java.util.List;

public interface MFAAuthenticator {

	// The wait time after an initial failed attempt that must pass before next try
	public long getTimeoutPeriod();
	
	public boolean isValid(String token, String secret);

	public String generateTOTP(String secret);

	public String generateSecret();

	public String combineSecrets(List<String> secrets);
}
