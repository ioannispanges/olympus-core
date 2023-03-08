package eu.olympus.unit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.olympus.model.*;
import eu.olympus.util.Util;
import org.junit.BeforeClass;
import org.junit.Test;
import org.miracl.core.BLS12461.BIG;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class TestAttributeDefinitions {

    private static Set<AttributeDefinition> definitions;
    private static AttributeDefinitionInteger defInteger;
    private static AttributeDefinitionBoolean defBoolean;
    private static AttributeDefinitionString defString;
    private static AttributeDefinitionDate defDate;
    private static final String withoutGranularitySerial="{\n" +
            "  \"id\" : \"url:DateOfBirth\",\n" +
            "  \"shortName\" : \"Date of Birth\",\n" +
            "  \"minDate\" : \"1950-01-01T00:00:00Z\",\n" +
            "  \"maxDate\" : \"2031-09-01T00:00:00Z\",\n" +
            "  \"type\" : \"Date\"\n" +
            "}";

    @BeforeClass
    public static void generateDefinitios(){
        definitions=new HashSet<>();
        defDate=new AttributeDefinitionDate("url:DateOfBirth","Date of Birth","1950-01-01T00:00:00","2031-09-01T00:00:00", DateGranularity.DAYS);
        defBoolean=new AttributeDefinitionBoolean("url:HasDrivingPermit","Has Driving Permit");
        defString=new AttributeDefinitionString("url:FamilyName","Family Name",2,16);
        defInteger=new AttributeDefinitionInteger("url:IntegerWithNegatives","Int",-20,300);
        definitions.add(defDate);
        definitions.add(defBoolean);
        definitions.add(defInteger);
        definitions.add(defString);
    }


    @Test
    public void testIntegerTransformation(){
        int val=300;
        Attribute attribute=new Attribute(val);
        long res=val+1-defInteger.getMinimumValue();
        BigInteger resBI=new BigInteger(""+res);
        //System.out.println(res);
        assertThat(defInteger.toBigIntegerRepresentation(attribute).compareTo(resBI),is(0));
    }

    @Test
    public void testDateTransformation(){
        AttributeDefinitionDate defDefault=new AttributeDefinitionDate("url:DateOfBirth","Date of Birth","1950-01-01T00:00:00","2031-09-01T00:00:00");
        long val=System.currentTimeMillis();
        Attribute attribute=new Attribute(new Date(val));
        long res=val/1000+1-defDate.getMinDate().getTime()/1000;
        BigInteger resBI=new BigInteger(""+res);
        assertThat(defDefault.toBigIntegerRepresentation(attribute).compareTo(resBI),is(0));
    }

    @Test
    public void testTruncatedDateTransformation(){
        AttributeDefinitionDate defMillis=new AttributeDefinitionDate("url:Date1","Date1","1950-01-01T12:34:56","2031-09-01T21:43:45",DateGranularity.MILLIS);
        AttributeDefinitionDate defSec=new AttributeDefinitionDate("url:Date2","Date2","1950-01-01T12:34:56","2031-09-01T21:43:45",DateGranularity.SECONDS);
        AttributeDefinitionDate defMin=new AttributeDefinitionDate("url:Date3","Date3","1950-01-01T12:34:56","2031-09-01T21:43:45",DateGranularity.MINUTES);
        AttributeDefinitionDate defHour=new AttributeDefinitionDate("url:Date4","Date4","1950-01-01T12:34:56","2031-09-01T21:43:45",DateGranularity.HOURS);
        AttributeDefinitionDate defDay=new AttributeDefinitionDate("url:Date5","Date5","1950-01-01T12:34:56","2031-09-01T21:43:45",DateGranularity.DAYS);
        Date now=new Date(System.currentTimeMillis());
        Attribute nowAttr=new Attribute(now);
        Attribute nowAttrMill=new Attribute(truncateToUnit(now,defMillis));
        Attribute nowAttrSec=new Attribute(truncateToUnit(now,defSec));
        Attribute nowAttrMin=new Attribute(truncateToUnit(now,defMin));
        Attribute nowAttrHour=new Attribute(truncateToUnit(now,defHour));
        Attribute nowAttrDay=new Attribute(truncateToUnit(now,defDay));
        assertThat(defMillis.toBigIntegerRepresentation(nowAttr).compareTo(defMillis.toBigIntegerRepresentation(nowAttrMill)),is(0));
        assertThat(defSec.toBigIntegerRepresentation(nowAttr).compareTo(defSec.toBigIntegerRepresentation(nowAttrSec)),is(0));
        assertThat(defMin.toBigIntegerRepresentation(nowAttr).compareTo(defMin.toBigIntegerRepresentation(nowAttrMin)),is(0));
        assertThat(defHour.toBigIntegerRepresentation(nowAttr).compareTo(defHour.toBigIntegerRepresentation(nowAttrHour)),is(0));
        assertThat(defDay.toBigIntegerRepresentation(nowAttr).compareTo(defDay.toBigIntegerRepresentation(nowAttrDay)),is(0));
    }

    private Date truncateToUnit(Date date, AttributeDefinitionDate def){
        return Date.from(date.toInstant().truncatedTo(def.getGranularity().getUnit()));
    }

    @Test
    public void testBooleanTransformation(){
        assertThat(defBoolean.toBigIntegerRepresentation(new Attribute(true)).compareTo(new BigInteger("1")),is(0));
        assertThat(defBoolean.toBigIntegerRepresentation(new Attribute(false)).compareTo(new BigInteger("2")),is(0));
    }

    @Test
    public void testStringTransformation(){
        String val="Blahblahblah";
        Attribute attribute=new Attribute(val);
        BigInteger res=defString.toBigIntegerRepresentation(attribute);
        BIG bigRes=Util.BigIntegerToBIG(res);
        assertThat(bigRes.toString().replaceFirst("^0+(?!$)", "").equals(res.toString(16).replaceFirst("^0+(?!$)", "")),is(true));
    }

    @Test
    public void testDateDefaultSerialization(){
        ObjectMapper mapper=new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        AttributeDefinitionDate defDefault=new AttributeDefinitionDate("url:DateOfBirth","Date of Birth","1950-01-01T00:00:00","2031-09-01T00:00:00");
        try {
            AttributeDefinition reconstructed=mapper.readValue(withoutGranularitySerial,new TypeReference<AttributeDefinition>(){});
            assertThat(reconstructed.equals(defDefault),is(true));
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testSerialization(){
        ObjectMapper mapper=new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        try {
            String serialized= mapper.writeValueAsString(definitions);
            //System.out.println(serialized);
            Set<AttributeDefinition> reconstructed=mapper.readValue(serialized,new TypeReference<Set<AttributeDefinition>>(){});
            assertThat(reconstructed.equals(definitions),is(true));
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }


    @Test
    public void testValdityChecksBoolean(){
        Attribute valid=new Attribute(true);
        Attribute differentType=new Attribute("No");
        assertThat(defBoolean.checkValidValue(valid),is(true));
        assertThat(defBoolean.checkValidValue(differentType),is(false));
    }


    @Test
    public void testValdityChecksDate(){
        Attribute valid=new Attribute(new Date(System.currentTimeMillis()));
        Attribute tooEarly=new Attribute(Util.fromRFC3339UTC("1920-01-01T00:00:00"));
        Attribute tooLate=new Attribute(Util.fromRFC3339UTC("2040-01-01T00:00:00"));
        Attribute differentType=new Attribute("No");
        assertThat(defDate.checkValidValue(valid),is(true));
        assertThat(defDate.checkValidValue(tooEarly),is(false));
        assertThat(defDate.checkValidValue(tooLate),is(false));
        assertThat(defDate.checkValidValue(differentType),is(false));
    }

    @Test
    public void testValdityChecksString(){
        Attribute valid=new Attribute("John");
        Attribute tooShort=new Attribute("a");
        Attribute tooLong=new Attribute("abcdefghijklmnopqrstuvwxy");
        Attribute differentType=new Attribute(true);
        assertThat(defString.checkValidValue(valid),is(true));
        assertThat(defString.checkValidValue(tooShort),is(false));
        assertThat(defString.checkValidValue(tooLong),is(false));
        assertThat(defString.checkValidValue(differentType),is(false));
    }

    @Test
    public void testValdityChecksInteger(){
        Attribute valid=new Attribute(180);
        Attribute tooSmall=new Attribute(-1000);
        Attribute tooBig=new Attribute(650);
        Attribute differentType=new Attribute("No");
        assertThat(defInteger.checkValidValue(valid),is(true));
        assertThat(defInteger.checkValidValue(tooSmall),is(false));
        assertThat(defInteger.checkValidValue(tooBig),is(false));
        assertThat(defInteger.checkValidValue(differentType),is(false));
    }

}
