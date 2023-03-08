package eu.olympus.unit.util;

import static org.junit.Assert.assertEquals;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import eu.olympus.TestParameters;
import eu.olympus.util.keyManagement.CertificateSerializer;
import eu.olympus.util.keyManagement.PemUtil;

public class TestCertificateSerializer{

	@Test
	public void testCertificateSerializer() throws IOException, CertificateEncodingException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		JsonGenerator gen = new JsonFactory().createGenerator(out);

		
		CertificateSerializer serializer = new CertificateSerializer();
		serializer.serialize(TestParameters.getRSA1Cert(), gen, null);
		gen.flush();

		String output = out.toString("UTF8");
		out.reset();
		
		String expected = PemUtil.encodeDerToPem(TestParameters.getRSA1Cert().getEncoded(), "CERTIFICATE");
		expected = "\""+expected.replaceAll("\n", "\\\\n")+"\"";
		assertEquals(expected, output);
		
		gen = new JsonFactory().createGenerator(out);
		serializer.serialize(null, gen, null);
		gen.flush();
		output = out.toString("UTF8");
		assertEquals("\"Error: null\"", output);
	}
	
}
