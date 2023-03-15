package eu.olympus.cfp.model;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.annotation.JsonIgnore;

import eu.olympus.model.server.rest.IdentityProof;

public class UserCertificate extends IdentityProof {


	private String data;
	
	public UserCertificate() {
	}

	public UserCertificate(Certificate cert) throws CertificateEncodingException {
		this.setCert(cert);
	}
	
	public UserCertificate(String data) {
		
	}

	public String getData() {
		return this.data;
	}
	
	public void setData(String data) {
		this.data = data;
	}
	
	@JsonIgnore
	public Certificate getCert() {
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}

		
		InputStream caInput = new ByteArrayInputStream(Base64.decodeBase64(data));
		Certificate ca = null;
		try {
			ca = cf.generateCertificate(caInput);
		} catch (CertificateException e) {
			e.printStackTrace();
		} finally {
			try {
				caInput.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return ca;
	}
	
	@JsonIgnore
	public void setCert(Certificate cert) throws CertificateEncodingException {
		this.data = Base64.encodeBase64String(cert.getEncoded());
		
	}
}
