package eu.olympus.oidc.model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;

import eu.olympus.model.Attribute;
import eu.olympus.model.server.rest.IdentityProof;

@JsonTypeInfo(use=Id.CLASS, include=As.PROPERTY, property="@class")
public class DemoIdentityProof extends IdentityProof {

	private String signature;
	@JsonTypeInfo(use=Id.CLASS, include=As.PROPERTY, property="class")
	private Map<String, Attribute> attributes;
	
	public DemoIdentityProof() {
	}
	
	public DemoIdentityProof(String signature, Map<String, Attribute> attributes) {
		super();
		this.signature = signature;
		this.attributes = attributes;
	}
	
	public Object getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public Map<String, Attribute> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, Attribute> attributes) {
		this.attributes = attributes;
	}
}
