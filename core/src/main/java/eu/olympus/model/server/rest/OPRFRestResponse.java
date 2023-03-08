package eu.olympus.model.server.rest;
import org.miracl.core.BLS12461.FP12;

public class OPRFRestResponse {

	private String ssid;
	private String element;
	private String sessionCookie;
	
	public OPRFRestResponse() {
		
	}
	
	public OPRFRestResponse(String ssid, String element, String sessionCookie) {
		this.ssid = ssid;
		this.element = element;
		this.sessionCookie = sessionCookie;
	}

	public String getSsid() {
		return ssid;
	}

	public void setSsid(String ssid) {
		this.ssid = ssid;
	}

	public String getElement() {
		return element;
	}

	public void setElement(String element) {
		this.element = element;
	}
	
	public static FP12 getAsElement(byte[] bytes) {
		FP12 x = FP12.fromBytes(bytes);
		return x;
	}

	public String getSessionCookie() {
		return sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}

}
