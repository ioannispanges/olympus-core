package eu.olympus.model.server.rest;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class AddPartialSignatureRequest {

	private String ssid;
	private String string;
	
	public AddPartialSignatureRequest() {
	}
	
	public AddPartialSignatureRequest(String ssid, String string) {
		this.ssid = ssid;
		this.string = string;
	}
	
	public String getSsid() {
		return ssid;
	}

	public void setSsid(String ssid) {
		this.ssid = ssid;
	}

	public String getString() {
		return string;
	}

	public void setString(String string) {
		this.string = string;
	}
	
	

}
