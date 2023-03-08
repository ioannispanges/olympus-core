package eu.olympus.server;

import de.taimos.totp.TOTP;
import eu.olympus.server.interfaces.MFAAuthenticator;
import eu.olympus.util.CommonCrypto;
import eu.olympus.util.Util;
import java.util.List;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

public class GoogleAuthenticator implements MFAAuthenticator {

	public static final String TYPE = "GOOGLE_AUTHENTICATOR";
	private static final int BYTES_IN_SECRET = 20;
	private final long mfaTimeout;
	private final CommonCrypto crypto;
	private final Base32 base32 = new Base32();

	public GoogleAuthenticator(CommonCrypto crypto) {
		this.crypto = crypto;
		mfaTimeout = 0;
	}

	public GoogleAuthenticator(CommonCrypto crypto, long timeout) {
		this.crypto = crypto;
		this.mfaTimeout = timeout;
	}

	@Override
	public boolean isValid(String token, String secret) {
		String totp = generateTOTP(secret);
		return totp.equals(token);
	}

	@Override
	public String generateTOTP(String secret) {
		byte[] bytes = base32.decode(secret);
		String hexKey = Hex.encodeHexString(bytes);
		return TOTP.getOTP(hexKey);
	}

	@Override
	public String generateSecret() {
		return base32.encodeToString(crypto.getBytes(BYTES_IN_SECRET));
	}

	@Override
	public String combineSecrets(List<String> secrets) {
		byte[] combinedSecret = base32.decode(secrets.remove(0));
		while(secrets.size() > 0) {
			combinedSecret = Util.xorArray(combinedSecret, base32.decode(secrets.remove(0)));
		}
		Base32 base32 = new Base32();
		return base32.encodeToString(combinedSecret);
	}

	@Override
	public long getTimeoutPeriod() {
		return mfaTimeout;
	}

}
