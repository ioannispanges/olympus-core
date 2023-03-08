package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.olympus.util.Util;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AttributeDefinitionDate extends AttributeDefinition {
    @JsonProperty("type") //Needed because of issue in Jackson with serialization of collections
    private final String type= "Date";
    private static final AttributeType TYPE= AttributeType.DATE;
    private static final DateGranularity DEFAULT_GRANULARITY= DateGranularity.SECONDS;
    @JsonProperty("minDate") private final String minDate;
    @JsonProperty("maxDate") private final String maxDate;
    @JsonProperty("granularity") private final DateGranularity granularity;

    private final Date parsedMinDate;
    private final Date parsedMaxDate;

    public AttributeDefinitionDate(@JsonProperty("id") String id,@JsonProperty("shortName") String shortName,@JsonProperty("minDate") String minDate,@JsonProperty("maxDate") String maxDate, @JsonProperty("granularity") DateGranularity granularity) {
        super(id, shortName);
        this.minDate = minDate;
        this.maxDate = maxDate;
        parsedMinDate= Util.fromRFC3339UTC(minDate);
        parsedMaxDate= Util.fromRFC3339UTC(maxDate);
        if(granularity==null)
            this.granularity=DEFAULT_GRANULARITY;
        else
            this.granularity=granularity;
    }

    public AttributeDefinitionDate(String id,String shortName,String minDate,String maxDate) {
        this(id,shortName,minDate,maxDate,null);

    }

    @JsonIgnore
    public Date getMinDate() {
        return parsedMinDate;
    }

    @JsonIgnore
    public Date getMaxDate() {
        return parsedMaxDate;
    }

    @JsonIgnore
    public DateGranularity getGranularity() {
        return granularity;
    }

    @Override
    public BigInteger toBigIntegerRepresentation(Attribute attribute) {
        //We assume that the range minDate-maxDate is small enough to be represented within [0,p] for ZpElement
        if(!checkValidValue(attribute))
            throw new IllegalArgumentException("Invalid attribute");
        Date val= (Date) attribute.getAttr();
        long unitFromEpoch=dateToTimeUnitFromEpoch(val);
        BigInteger res=BigInteger.valueOf(unitFromEpoch);
        res=res.add(new BigInteger("1"));
        res=res.subtract(BigInteger.valueOf(dateToTimeUnitFromEpoch(parsedMinDate)));
        return res;
    }

    @Override
    public boolean checkValidValue(Attribute value) {
        if(value.getType()!=TYPE|| !(value.getAttr() instanceof Date))
            return false;
        Date val= (Date) value.getAttr();
        if(val.equals(parsedMaxDate)|| val.equals(parsedMinDate))
            return true;
        return val.after(parsedMinDate) && val.before(parsedMaxDate);
    }

    private long dateToTimeUnitFromEpoch(Date date){
        return granularity.between(Instant.EPOCH,date.toInstant());
    }


}
