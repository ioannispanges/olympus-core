package eu.olympus.util.rangeProof;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import eu.olympus.model.Attribute;
import eu.olympus.util.pairingInterfaces.PairingBuilder;
import eu.olympus.util.pairingInterfaces.ZpElement;
import org.junit.Test;

public class RangeVerifierTest {

    @Test(expected = IllegalArgumentException.class)
    public void checkRangeWrongType() {
        PairingBuilder builder = mock(PairingBuilder.class);
        doReturn(mock(ZpElement.class)).when(builder).getZpElementOne();
        RangeVerifier rangeVerifier = new RangeVerifier("salt", builder);
        rangeVerifier.checkRange(new Attribute("aString"),new Attribute("aString"));
    }
}
