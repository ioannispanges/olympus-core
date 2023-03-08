package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonRootName;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import eu.olympus.model.server.rest.IdentityProof;
import java.util.Map;

@JsonTypeInfo(use= Id.CLASS, include= As.PROPERTY, property="@class")
@JsonRootName(value="AttributeIdentityProof")
public class AttributeIdentityProof extends IdentityProof {

    @JsonTypeInfo(use=Id.CLASS, include=As.PROPERTY, property="class")
    private Map<String, Attribute> attributes;

    public AttributeIdentityProof(){}

    public AttributeIdentityProof(Map<String, Attribute> attributes) {
        super();
        this.attributes = attributes;
    }
    public Map<String, Attribute> getAttributes() {
        return attributes;
    }

}
