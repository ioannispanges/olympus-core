package eu.olympus.cfp.model;

import eu.olympus.model.server.rest.IdentityProof;

public class CreditFile extends IdentityProof {

	private String data;

	public CreditFile() {
	}
	
	public CreditFile(String data) {
		this.data = data;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}
	
}
