package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;

public class AttributeDefinitionInteger extends AttributeDefinition {

    @JsonProperty("type") //Needed because of issue in Jackson with serialization of collections
    private final String type= "Integer";
    private final AttributeType TYPE= AttributeType.INTEGER;
    private final int minimumValue;
    private final int maximumValue;

    public AttributeDefinitionInteger(@JsonProperty("id") String id, @JsonProperty("shortName") String shortName,@JsonProperty("min") int minimumValue,@JsonProperty("max") int maximumValue) {
        super(id, shortName);
        this.minimumValue = minimumValue;
        this.maximumValue = maximumValue;
    }

    public int getMinimumValue() {
        return minimumValue;
    }

    public int getMaximumValue() {
        return maximumValue;
    }

    @Override
    public BigInteger toBigIntegerRepresentation(Attribute attribute) {
        //We assume that the range [minimumValue,maximumValue] is small enough to be represented within [1,p] for ZpElement
        if(!checkValidValue(attribute))
            throw new IllegalArgumentException("Invalid attribute");
        BigInteger res=new BigInteger(attribute.getAttr().toString());
        res=res.add(new BigInteger("1"));
        res=res.subtract(BigInteger.valueOf(minimumValue));
        return res;
    }


    @Override
    public boolean checkValidValue(Attribute value) {
        if(value.getType()!=TYPE|| !(value.getAttr() instanceof Integer))
            return false;
        Integer val= (Integer) value.getAttr();
        return val>=minimumValue && val<=maximumValue ;
    }


}
