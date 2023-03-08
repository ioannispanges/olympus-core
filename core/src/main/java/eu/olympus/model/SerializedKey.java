package eu.olympus.model;

import eu.olympus.server.rest.PabcIdPServlet;
import java.nio.ByteBuffer;

import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.Charsets;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@JsonIgnoreProperties(ignoreUnknown=true)
public class SerializedKey {

	private static final Logger logger = LoggerFactory.getLogger(PabcIdPServlet.class);

	private String algorithm;
	private String format;
	private String encoded;

	public SerializedKey(){
		this.algorithm = null;
		this.format = null;
		this.encoded = null;
	}

	public SerializedKey(byte[] serialized){
		String serializedString = new String(serialized);
		String[] arr = serializedString.split("\\r?\\n");;
		format = arr[0];
		algorithm = arr[1];
		encoded = arr[2].trim();
	}
	
	public SerializedKey(String algorithm, String format, String encoded) {
		if(algorithm.contains("\\r?\\n") || format.contains("\\r?\\n")){
			logger.error("Algorithm or format contains an illegal string");
			throw new IllegalArgumentException("Algorithm or format contains an illegal string");
		}
		this.algorithm = algorithm;
		this.format = format;
		this.encoded = encoded;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getFormat() {
		return format;
	}

	public void setFormat(String format) {
		this.format = format;
	}

	public String getEncoded() {
		return encoded;
	}

	public void setEncoded(String encoded) {
		this.encoded = encoded;
	}
	
	public byte[] getBytes() {
		ByteBuffer buf = ByteBuffer.allocate(getEncoded().getBytes(Charsets.UTF_8).length+200);
		buf.put(getFormat().getBytes(Charsets.UTF_8));
		buf.put("\n".getBytes(StandardCharsets.UTF_8));
		buf.put(getAlgorithm().getBytes(Charsets.UTF_8));
		buf.put("\n".getBytes(StandardCharsets.UTF_8));
		buf.put(getEncoded().getBytes(Charsets.UTF_8));
		return buf.array();
	}

}
