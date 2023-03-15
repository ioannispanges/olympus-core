package eu.olympus.cfp;

import eu.olympus.util.keyManagement.CertificateUtil;
import java.security.KeyFactory;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;


public class TestParameters {
	// 127.0.0.1 is needed to make the TLS REST tests pass
	private static final String RDN = "CN=127.0.0.1,O=Olympus,OU=www.olympus-project.eu,C=EU";

	public static final String TEST_KEY_STORE_LOCATION = "src/test/resources/volatile/keystore.jks";
	public static final String TEST_KEY_STORE_PWD = "server1";
	public static final String TEST_TRUST_STORE_LOCATION = "src/test/resources/truststore.jks";
	public static final String TEST_TRUST_STORE_PWD = "OLYMPUS";
	public static final String TEST_DIR = "src/test/resources/";
	public static final String RSA1_CERT_DIR = TEST_DIR +"volatile/testSelfSigned1.crt";
	public static final String RSA2_CERT_DIR = TEST_DIR +"volatile/testSelfSigned2.crt";
	public static final String RSA1_PRIV_DIR = TEST_DIR +"volatile/testRsa1.pem";
	public static final String RSA2_PRIV_DIR = TEST_DIR +"volatile/testRsa2.pem";

	private static final String ecPublic1String = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4aQEOaEzwM+VrFFAYUfkghzU0YIy3oLLk9Lx62qo0YYrNkJPsybMtaXWpJ+87sQiQzq4Qa5rIAdnjmtpk7FTIA==";
	private static final String ecPrivate1String = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDuqZgC/yIbCGCiU/gYNo2wnwrWStXprhT55UDi83zmCA==";
	private static final String ecPublic2String = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDytXLP30tcqSNA5lbjp1fHTtbalJdyEEGrTZtkNJoHI8LFmnsuO0TUWOBaES4pPheqa+ebGRxXspvvhJT3lNiQ==";
	private static final String ecPrivate2String = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDf3SvbGDpLMW2d0e8jZ77pI8d8rn+rehbZIFdcVNF54Q==";

	private static final String rsaPublic1String = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiS5johSik9uP5zDh7XeWvzq6cP+gjSIkzq691v98TzREI0wjrtZgXnUY4EZyF9th8LDGvmpul4aCJUPlGb3MP4CjbG068ZDXQwf5i5fLsAsTkG4JJgB6G+KfeFt7SUcuM4AwdT7KIVItPb/sa8sOXkF0b9w5+Du4MNZ0WE8y46tPr3lAPJdsnmsRhWTwyybGG6nOjEg3pq8i//C6cqpWO1KhOiycX1nop5owidO8naCgwwvXEeThMFCslAfpqN/jqqz07PLiaRUcL2YVdHd3daboYkiGr0IOrQdc1GyweIaTjPjdwJy+MxvL3kYZVwkHlZge2NG7IeZQiOe+iLWfmQ4OWyCK/WTBkddt99SbVc3KmX/2KUr5dtM4XGRXZptTrsOx5zXZ+gIO5amBUP/F84obJdOsmxFVJWuCdGkniUD1Z2OGbaIMnVJCZe+xn7oZi7nuv4D9dg0I29bwslz50EMByBSaNh+JwUZ9CkGSuIaiZp9Ao0mdFOC6cUmnFHIrAgMBAAE=";
	private static final String rsaPrivate1String = "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";
	private static final String rsaPublic2String = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAq/KU21UGtGroMJqUcLTR2Q3WdhxQFHXIm/KESHTSOatrUOkFMBlNoPhDo0dKTzthu89prfUSC+ZCrkQH3A1T9fKYmkQwFudkBbp77N88NV5TfnGMjZJgqTSjKhI4pNBPwUjthsL0QSTIhc9A7kurtM0QlGCpqBMRtdDIaa6VddI35Zi7s+Y3d9QP/LSg4rnXGBc5eZPyfPdhJWh0D3er9EtXAI1Qf8EqTHLT7LRzdbN84hZJCGpkl0GvN0Gg7RHFIdVTPmPQxhdaalgNW8K0IZdZNZMzeqPqIknDWG30zd7fXGUuEEA0u3RZnLS6AToW4+jPVXLPTJHWPS+zHjbluIUNYf1yMJyebgcpWQ3A4wdyzwlNrqMCRRC0xBLYuVlJLl0WjeWXEQ8UpeS5nV+r7/rbQ29kdqgAC7qYG3R19Qb5SrtFa7xZnoqh4Kd22k8i4EjfxSPQoHVFaSlaVbBoPt+XWKI5c+ER+vG1waiWMPEVJAKIw6blmpQf6gtW7h2lAgMBAAE=";
	private static final String rsaPrivate2String = "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";

	private static TestParameters params = null;
	private RSAPublicKey rsaPublic1;
	private RSAPublicKey rsaPublic2;
	private RSAPrivateKey rsaPrivate1;
	private RSAPrivateKey rsaPrivate2;
	private ECPublicKey ecPublic1;
	private ECPublicKey ecPublic2;
	private ECPrivateKey ecPrivate1;
	private ECPrivateKey ecPrivate2;

	private Certificate rsaCert1;
	private Certificate rsaCert2;

	private TestParameters() {
		try {
			KeyFactory factory = KeyFactory.getInstance("EC");
			ecPublic1 = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(b64de(ecPublic1String)));
			ecPrivate1 = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(b64de(ecPrivate1String)));

			ecPublic2 = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(b64de(ecPublic2String)));
			ecPrivate2 = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(b64de(ecPrivate2String)));

			factory = KeyFactory.getInstance("RSA");
			rsaPublic1 = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(b64de(rsaPublic1String)));
			rsaPrivate1 = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(b64de(rsaPrivate1String)));
			PKCS10CertificationRequest csr1 = CertificateUtil
					.makeCSR(rsaPrivate1, rsaPublic1, RDN, null);
			rsaCert1 = CertificateUtil.makeSelfSignedCert(rsaPrivate1, csr1);

			rsaPublic2 = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(b64de(rsaPublic2String)));
			rsaPrivate2 = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(b64de(rsaPrivate2String)));
			PKCS10CertificationRequest csr2 = CertificateUtil
					.makeCSR(rsaPrivate2, rsaPublic2, RDN, null);
			rsaCert2 = CertificateUtil.makeSelfSignedCert(rsaPrivate2, csr2);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static RSAPublicKey getRSAPublicKey1() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.rsaPublic1;
	}

	public static RSAPublicKey getRSAPublicKey2() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.rsaPublic2;
	}

	public static RSAPrivateKey getRSAPrivateKey1() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.rsaPrivate1;
	}

	public static RSAPrivateKey getRSAPrivateKey2() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.rsaPrivate2;
	}

	public static Certificate getRSA1Cert() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.rsaCert1;
	}

	public static Certificate getRSA2Cert() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.rsaCert2;
	}

	public static ECPublicKey getECPublicKey1() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.ecPublic1;
	}

	public static ECPrivateKey getECPrivateKey1() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.ecPrivate1;
	}

	public static ECPublicKey getECPublicKey2() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.ecPublic2;
	}

	public static ECPrivateKey getECPrivateKey2() {
		if(params == null) {
			params = new TestParameters();
		}
		return params.ecPrivate2;
	}


	private static byte[] b64de(String input) {
		return Base64.decodeBase64(input);
	}
}
