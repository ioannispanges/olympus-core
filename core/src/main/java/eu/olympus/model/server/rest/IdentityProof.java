package eu.olympus.model.server.rest;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.xml.bind.annotation.XmlRootElement;

@JsonTypeInfo(use = Id.CLASS,
	include = JsonTypeInfo.As.PROPERTY,
	property = "@class")
@XmlRootElement
public class IdentityProof {
	
	@JsonIgnore
	public String getStringRepresentation() {
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			return objectMapper.writeValueAsString(this);
		}catch(JsonProcessingException e) {
			return "";
		}
	}
	
}