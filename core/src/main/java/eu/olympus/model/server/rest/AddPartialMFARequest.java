package eu.olympus.model.server.rest;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class AddPartialMFARequest {

	private String ssid;
	private String string;
	private String type;
	
	public AddPartialMFARequest() {
	}
	
	public AddPartialMFARequest(String ssid, String string, String type) {
		this.ssid = ssid;
		this.string = string;
		this.type = type;
	}
	
	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
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
