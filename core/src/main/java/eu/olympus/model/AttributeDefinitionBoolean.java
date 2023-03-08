package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;

public class AttributeDefinitionBoolean extends AttributeDefinition {

    @JsonProperty("type") //Needed because of issue in Jackson with serialization of collections
    private final String type= "Boolean";
    private final AttributeType TYPE= AttributeType.BOOLEAN;

    @JsonCreator
    public AttributeDefinitionBoolean(@JsonProperty("id") String id,@JsonProperty("shortName") String shortName) {
        super(id, shortName);
    }

    @Override
    public BigInteger toBigIntegerRepresentation(Attribute attribute) {
        if(!checkValidValue(attribute))
            throw new IllegalArgumentException("Invalid attribute");
        BigInteger res= attribute.getAttr().equals(true) ? new BigInteger("1") : new BigInteger("2");
        return res;
    }



    @Override
    public boolean checkValidValue(Attribute value) {
        if(value.getType()!=TYPE|| !(value.getAttr() instanceof Boolean))
            return false;
        return true;
    }
}
