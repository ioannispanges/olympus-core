package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.math.BigInteger;


// I think the best way (for now) to allow restrictions for different attribute types (minimum and maximum for integer/date, nothing
// for boolean, min and max length for string, maybe number of decimals for real...) is using a hierarchical class definition, though this
// differs from the previous approach for "Attribute". After working with W3C approach, we may get another solution suitable for all cases
/**
 * Defines an attribute used in the p-ABC approach (may also be useful for Pesto). The id value is the main identifying property,
 * and must be unique in a deployment (e.g. deploymentSpecificUrl:DateOfBirth). Subclasses for specific "types" of attributes (string, date...)
 * will define extra fields for restrictions on attribute values (which may also be needed for translating a value into a Zp representation).
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AttributeDefinitionString.class, name="String"),
        @JsonSubTypes.Type(value = AttributeDefinitionInteger.class, name="Integer"),
        @JsonSubTypes.Type(value = AttributeDefinitionBoolean.class, name="Boolean"),
        @JsonSubTypes.Type(value = AttributeDefinitionDate.class, name="Date")
})
public abstract class AttributeDefinition {

    private final String id;
    private final String shortName;


    protected AttributeDefinition(String id, String shortName) {
        this.id = id;
        this.shortName = shortName;
    }

    public String getId() {
        return id;
    }

    public String getShortName() {
        return shortName;
    }


    //Instead of exception when attribute is not valid, returning 0 (which we consider as "no value") might be enough
    public abstract BigInteger toBigIntegerRepresentation(Attribute attribute);

    public abstract boolean checkValidValue(Attribute value);

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        AttributeDefinition objAttDef=(AttributeDefinition)obj;
        return this.id.equals(objAttDef.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
