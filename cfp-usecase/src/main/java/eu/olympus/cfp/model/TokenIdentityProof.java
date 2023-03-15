package eu.olympus.cfp.model;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;

import eu.olympus.model.server.rest.IdentityProof;

@JsonTypeInfo(use=Id.CLASS, include=As.PROPERTY, property="@class")
public class TokenIdentityProof extends IdentityProof {

	private String value;
	
	public TokenIdentityProof() {
	}
	
	public TokenIdentityProof(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}
	
}
