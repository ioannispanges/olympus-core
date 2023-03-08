package eu.olympus.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeIdentityProof;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.interfaces.Storage;
import eu.olympus.unit.server.TestIdentityProof;
import eu.olympus.unit.server.TestIdentityProver;
import eu.olympus.util.Util;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class AttributeIdentityProverTest {

    private Map<String, Attribute> attributeMap() {
        Map<String, Attribute> attributes = new HashMap<>();
        attributes.put("name", new Attribute("John Doe"));
        attributes.put("email", new Attribute("John.Doe@example.com"));
        attributes.put("birthdate",new Attribute(Util.fromRFC3339UTC("1998-01-05T00:00:00")));
        return attributes;
    }

    @Test
    public void isValid() {
        AttributeIdentityProof aProof = new AttributeIdentityProof(attributeMap());

        Storage mockStorage = mock(Storage.class);
        AttributeIdentityProver aProver = new AttributeIdentityProver(mockStorage);
        assertTrue(aProver.isValid(aProof.getStringRepresentation(),"user"));
    }

    @Test
    public void isValidWrongIdentityProof() {
        // aProof does not contain a valid AttributeIdentityProof, hence the verification fails
        TestIdentityProof aProof = new TestIdentityProof();
        Storage mockStorage = mock(Storage.class);
        AttributeIdentityProver aProver = new AttributeIdentityProver(mockStorage);
        assertFalse(aProver.isValid(aProof.getStringRepresentation(),"user"));
    }

    @Test
    public void addAttributes() throws OperationFailedException {
        AttributeIdentityProof aProof = new AttributeIdentityProof(attributeMap());

        Storage mockStorage = mock(Storage.class);
        AttributeIdentityProver aProver = new AttributeIdentityProver(mockStorage);
        aProver.addAttributes(aProof.getStringRepresentation(),"user");

        ArgumentCaptor<Map<String,Attribute>> captor = ArgumentCaptor.forClass(Map.class);
        verify(mockStorage,times(1)).addAttributes(anyString(),captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("John Doe",captor.getValue().get("name").getAttr());
        assertEquals("John.Doe@example.com",captor.getValue().get("email").getAttr());
    }

    @Test
    public void addAttributesWrongIdentityProof() {
        // aProof does not contain a TestIdentityProof, hence addAttributes cannot be carried out
        AttributeIdentityProof aProof = new AttributeIdentityProof(attributeMap());

        Storage mockStorage = mock(Storage.class);

        TestIdentityProver aProver = new TestIdentityProver(mockStorage);
        assertThrows(RuntimeException.class, ()-> aProver.addAttributes(aProof.getStringRepresentation(),"user"));
    }
}
