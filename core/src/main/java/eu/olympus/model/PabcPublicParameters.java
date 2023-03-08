package eu.olympus.model;

import java.util.Set;

public class PabcPublicParameters {

    private Set<AttributeDefinition> attributeDefinitions;
    private String encodedSchemePublicParam;

    public PabcPublicParameters() {
    }

    public PabcPublicParameters(Set<AttributeDefinition> attributeDefinitions, String encodedSchemePublicParam) {
        this.attributeDefinitions = attributeDefinitions;
        this.encodedSchemePublicParam = encodedSchemePublicParam;
    }

    public Set<AttributeDefinition> getAttributeDefinitions() {
        return attributeDefinitions;
    }

    public void setAttributeDefinitions(Set<AttributeDefinition> attributeDefinitions) {
        this.attributeDefinitions = attributeDefinitions;
    }

    public String getEncodedSchemePublicParam() {
        return encodedSchemePublicParam;
    }

    public void setEncodedSchemePublicParam(String encodedSchemePublicParam) {
        this.encodedSchemePublicParam = encodedSchemePublicParam;
    }
}
