package eu.olympus.model;

import org.miracl.core.BLS12461.FP12;

public class OPRFResponse {

	private FP12 y;
	private String ssid;
	private String sessionCookie;

	public OPRFResponse(){
		
	}
	
	public OPRFResponse(FP12 y, String ssid, String sessionCookie) {
		super();
		this.y = y;
		this.ssid = ssid;
		this.sessionCookie = sessionCookie;
	}

	public String getSsid() {
		return ssid;
	}

	public void setSsid(String ssid) {
		this.ssid = ssid;
	}

	public void setY(FP12 y) {
		this.y = y;
	}

	public FP12 getY() {
		return y;
	}

	public String getSessionCookie() {
		return this.sessionCookie;
	}

	public void setSessionCookie(String sessionCookie) {
		this.sessionCookie = sessionCookie;
	}
}
