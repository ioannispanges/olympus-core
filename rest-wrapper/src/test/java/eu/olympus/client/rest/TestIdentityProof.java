package eu.olympus.client.rest;


import java.util.Map;

import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;

import eu.olympus.model.Attribute;
import eu.olympus.model.server.rest.IdentityProof;

import com.fasterxml.jackson.annotation.JsonTypeInfo.As;

@JsonTypeInfo(use=Id.CLASS, include=As.PROPERTY, property="@class")
@JsonRootName(value="TestIdentityProof")
public class TestIdentityProof extends IdentityProof{

	private String signature;
	@JsonTypeInfo(use=Id.CLASS, include=As.PROPERTY, property="class")
	private Map<String, Attribute> attributes;
	
	public TestIdentityProof(){
	}
	
	public TestIdentityProof(String signature, Map<String, Attribute> attributes) {
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
	/* Leftover from pabc. Is it needed with the new IdentityProofing?
	public TestIdentityProof(String idProof) throws InvalidProtocolBufferException {
		PabcSerializer.IdentityProof protoIdProof=PabcSerializer.IdentityProof.parseFrom(Base64.decodeBase64(idProof));
		this.signature=protoIdProof.getSignature();
		this.attributes=new HashMap<>();
		Map<String,PabcSerializer.Attribute> protoAttr=protoIdProof.getAttributesMap();
		for (String attr:protoAttr.keySet()){
			this.attributes.put(attr,new Attribute(protoAttr.get(attr)));
		}
	}

	@Override
	public String toString() {
		return Base64.encodeBase64String(toProto().toByteArray());
	}

	private PabcSerializer.IdentityProof toProto(){
		Map<String,PabcSerializer.Attribute> protoAttributes=new HashMap<>();
		for(String attrName:attributes.keySet())
			protoAttributes.put(attrName,attributes.get(attrName).toProto());
		return PabcSerializer.IdentityProof.newBuilder()
				.setSignature(signature)
				.putAllAttributes(protoAttributes)
				.build();
	}*/
	
}
