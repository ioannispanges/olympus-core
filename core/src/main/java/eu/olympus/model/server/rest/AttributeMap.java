package eu.olympus.model.server.rest;

import java.util.Map;

import eu.olympus.model.Attribute;

public class AttributeMap {

	private Map<String, Attribute> attributes;
	
	public AttributeMap() {
	}
	
	public AttributeMap(Map<String, Attribute> attributes) {
		this.setAttributes(attributes);
	}

	public Map<String, Attribute> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, Attribute> attributes) {
		this.attributes = attributes;
	}
	
}
