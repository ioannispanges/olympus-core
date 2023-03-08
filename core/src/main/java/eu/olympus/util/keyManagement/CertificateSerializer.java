package eu.olympus.util.keyManagement;

import java.io.IOException;
import java.security.cert.Certificate;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class CertificateSerializer extends JsonSerializer<Certificate>{

	@Override
	public void serialize(Certificate value, JsonGenerator gen, SerializerProvider serializers)
			throws IOException, JsonProcessingException {
		try {
			String write = PemUtil.encodeDerToPem(value.getEncoded(), "CERTIFICATE");
			gen.writeString(write);
		} catch(Exception e) {
			gen.writeString("Error: "+e.getLocalizedMessage());
		}
	}

}
