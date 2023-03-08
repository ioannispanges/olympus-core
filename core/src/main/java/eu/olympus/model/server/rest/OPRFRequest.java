package eu.olympus.model.server.rest;

public class OPRFRequest {

	private String ssid;
	private String username;
	private String element;
	private String mfaToken;
	private String mfaType;
	private String sessionCookie;

	public OPRFRequest() {
	}
	
	public OPRFRequest(String ssid, String username, String element) {
		this.ssid = ssid;
		this.username = username;
		this.element = element;
	}

	public String getSsid() {
		return ssid;
	}

	public void setSsid(String ssid) {
		this.ssid = ssid;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getElement() {
		return element;
	}
	
	public void setElement(String element) {
		this.element = element;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}

	public String getMfaType() {
		return mfaType;
	}

	public void setMfaType(String mfaType) {
		this.mfaType = mfaType;
	}

	public String getMfaToken() {
		return mfaToken;
	}

	public void setMfaToken(String mfaToken) {
		this.mfaToken = mfaToken;
	}
}
