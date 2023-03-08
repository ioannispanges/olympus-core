package eu.olympus.unit.util;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.TestParameters;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.util.keyManagement.CertificateUtil;
import eu.olympus.util.keyManagement.KeyUtil;
import eu.olympus.util.keyManagement.PemUtil;
import eu.olympus.util.keyManagement.SecureStoreUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.regex.Pattern;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestKeyManagementUtils {

  @BeforeClass
  public static void setupSecurityStores() throws Exception {
    SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
    rand.setSeed("seed".getBytes());
    KeyUtil harness = new KeyUtil(rand);

    KeyStore trustStore = SecureStoreUtil.getEmptySecurityStore();
    trustStore.setCertificateEntry("olympus1", TestParameters.getRSA1Cert());
    trustStore.setCertificateEntry("olympus2", TestParameters.getRSA2Cert());
    trustStore.setCertificateEntry("server1", TestParameters.getRSA1Cert());
    SecureStoreUtil.writeSecurityStore(trustStore, TestParameters.TEST_TRUST_STORE_PWD, TestParameters.TEST_TRUST_STORE_LOCATION);

    // Make a fresh, empty keystore
    KeyStore keyStore = SecureStoreUtil.getEmptySecurityStore();
    SecureStoreUtil.writeSecurityStore(keyStore, TestParameters.TEST_KEY_STORE_PWD, TestParameters.TEST_KEY_STORE_LOCATION);

    Files.createDirectories(Paths.get(TestParameters.RSA1_CERT_DIR).getParent());
    Files.write(Paths.get(TestParameters.RSA1_CERT_DIR),
        PemUtil.encodeDerToPem(TestParameters.getRSA1Cert().getEncoded(), "CERTIFICATE").getBytes(
        StandardCharsets.US_ASCII), CREATE, WRITE, TRUNCATE_EXISTING);
    Files.createDirectories(Paths.get(TestParameters.RSA2_CERT_DIR).getParent());
    Files.write(Paths.get(TestParameters.RSA2_CERT_DIR),
        PemUtil.encodeDerToPem(TestParameters.getRSA2Cert().getEncoded(), "CERTIFICATE").getBytes(
            StandardCharsets.US_ASCII), CREATE, WRITE, TRUNCATE_EXISTING);

    String key1 = harness.makePKCS8PemKey(TestParameters.getRSAPrivateKey1(), TestParameters.TEST_KEY_STORE_PWD);
    Files.createDirectories(Paths.get(TestParameters.RSA1_PRIV_DIR).getParent());
    Files.write(Paths.get(TestParameters.RSA1_PRIV_DIR),
        key1.getBytes(StandardCharsets.US_ASCII), CREATE, WRITE, TRUNCATE_EXISTING);
    String key2 = harness.makePKCS8PemKey(TestParameters.getRSAPrivateKey2(), TestParameters.TEST_KEY_STORE_PWD);
    Files.createDirectories(Paths.get(TestParameters.RSA2_PRIV_DIR).getParent());
    Files.write(Paths.get(TestParameters.RSA2_PRIV_DIR),
        key2.getBytes(StandardCharsets.US_ASCII), CREATE, WRITE, TRUNCATE_EXISTING);

    SecureStoreUtil
        .writeCertificateToStore("server1", TestParameters.TEST_DIR +"server1.crt", TestParameters.TEST_TRUST_STORE_LOCATION, TestParameters.TEST_TRUST_STORE_PWD);
    SecureStoreUtil.writeKeyToStore("rsa1", TestParameters.RSA1_PRIV_DIR, TestParameters.RSA1_CERT_DIR, TestParameters.TEST_KEY_STORE_LOCATION, TestParameters.TEST_KEY_STORE_PWD, TestParameters.TEST_KEY_STORE_PWD);
    SecureStoreUtil.writeKeyToStore("rsa2", TestParameters.RSA2_PRIV_DIR, TestParameters.RSA2_CERT_DIR, TestParameters.TEST_KEY_STORE_LOCATION, TestParameters.TEST_KEY_STORE_PWD,  TestParameters.TEST_KEY_STORE_PWD);

  }

  @Test
  public void testSunshineSelfSigned() throws Exception {
    CertificateUtil certificateUtil = new CertificateUtil(
        TestParameters.TEST_TRUST_STORE_LOCATION, TestParameters.TEST_TRUST_STORE_PWD);
    Certificate cert = CertificateUtil.loadCertificate(TestParameters.RSA1_CERT_DIR);
    // Throws an exception if the verification does not succeed
    // Verify that the cert is signed by its own key
    cert.verify(cert.getPublicKey());
    assertTrue(certificateUtil.verifyAndValidateCert((X509Certificate) cert));
  }

  @Test
  public void testSunshineSelfSignedNoPassword() throws Exception {
    CertificateUtil certificateUtil = new CertificateUtil(TestParameters.TEST_TRUST_STORE_LOCATION);
    Certificate cert = CertificateUtil.loadCertificate(TestParameters.RSA1_CERT_DIR);
    // Throws an exception if the verification does not succeed
    // Verify that the cert is signed by its own key
    cert.verify(cert.getPublicKey());
    assertTrue(certificateUtil.verifyAndValidateCert((X509Certificate) cert));
  }


  // NOTE THIS TEST WILL FAIL ONCE THE TESTCERT EXPIRES
  // In that case it needs to be replaced. Currently, the test just uses Comodo's CA cert
  @Test
  public void testSunshineChain() throws Exception {
    // Load the keystore with all the root certs
    CertificateUtil certificateUtil = new CertificateUtil(TestParameters.REAL_TRUST_STORE_LOCATION, TestParameters.REAL_TRUST_STORE_PWD);
    X509Certificate cert = (X509Certificate) CertificateUtil
        .loadCertificate(TestParameters.TEST_DIR +"testCert.crt");
    assertTrue(certificateUtil.verifyAndValidateCertChain(Arrays.asList(cert)));
  }

  // NOTE THIS TEST WILL FAIL ONCE THE REVOKED CERT EXPIRES
  @Test
  public void testRevoked() throws Exception {
    SecureStoreUtil.writeCertificateToStore("revoked test root", TestParameters.TEST_DIR +"testRevokedRoot.cer", TestParameters.TEST_TRUST_STORE_LOCATION, TestParameters.TEST_TRUST_STORE_PWD);
    CertificateUtil certificateUtil = new CertificateUtil(
        TestParameters.TEST_TRUST_STORE_LOCATION, TestParameters.TEST_TRUST_STORE_PWD);
    X509Certificate cert = (X509Certificate) CertificateUtil
        .loadCertificate(TestParameters.TEST_DIR +"testRevoked.cer");
    X509Certificate intermidiateCert = (X509Certificate) CertificateUtil.loadCertificate(
        TestParameters.TEST_DIR +"testRevokedIntermidiate.cer");
    assertFalse(certificateUtil.verifyAndValidateCertChain(Arrays.asList(cert, intermidiateCert)));
    // Ensure the failure is because of revocation
    try {
      certificateUtil.verifyCertChain(Arrays.asList(cert, intermidiateCert));
      fail();
    } catch (CertificateException e) {
      assertTrue(e.getCause() instanceof CertPathValidatorException);
    }
  }

  @Test
  public void systemTrustStoreWontAcceptSelfSigned() throws Exception {
    // Load the system's trust store, which does not contain the certificate
    CertificateUtil loader = new CertificateUtil(TestParameters.REAL_TRUST_STORE_LOCATION, TestParameters.REAL_TRUST_STORE_PWD);
    Certificate cert = CertificateUtil.loadCertificate(TestParameters.RSA1_CERT_DIR);
    // The signature on the cert should be ok
    cert.verify(cert.getPublicKey());
    // But the cert should not verify against the trust store
    assertFalse(loader.verifyAndValidateCert((X509Certificate) cert));
  }

  @Test(expected = SetupException.class)
  public void testWrongPwd() throws Exception {
    new CertificateUtil(TestParameters.TEST_TRUST_STORE_LOCATION, "notcorrect");
  }

  @Test
  public void testPemEncoding() throws Exception {
    Certificate cert = CertificateUtil.loadCertificate(TestParameters.RSA2_CERT_DIR);
    String encodedCert = PemUtil.encodeDerToPem(cert.getEncoded(), "CERTIFICATE");
    Certificate newCert = CertificateUtil.decodePemCert(encodedCert);
    assertArrayEquals(cert.getEncoded(), newCert.getEncoded());
  }

  @Test
  public void testCSR() throws Exception {
    PKCS10CertificationRequest csr = CertificateUtil
        .makeCSR(TestParameters.getRSAPrivateKey1(), TestParameters.getRSAPublicKey1(),
        "CN=www.olympus-idp.eu,O=Olympus,OU=www.olympus-project.eu,C=EU", null);
    Certificate cert = CertificateUtil.makeSelfSignedCert(TestParameters.getRSAPrivateKey1(), csr);
    // Throws exception in case of failure
    cert.verify(TestParameters.getRSAPublicKey1());
  }

  @Test
  public void testIpRegex() throws Exception {
    Pattern IP_PATTERN= Pattern.compile("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)(\\.(?!$)|$)){4}$");
    assertTrue(IP_PATTERN.matcher("10.0.2.2").matches());
    assertTrue(IP_PATTERN.matcher("155.55.1.52").matches());
    assertTrue(IP_PATTERN.matcher("192.168.1.1").matches());
    assertTrue(IP_PATTERN.matcher("0.0.0.0").matches());
    assertTrue(IP_PATTERN.matcher("1.1.1.1").matches());
    assertFalse(IP_PATTERN.matcher("localhost").matches());
    assertFalse(IP_PATTERN.matcher("ip10.0.0.2").matches());
    assertFalse(IP_PATTERN.matcher("01.2.3.1").matches());
    assertFalse(IP_PATTERN.matcher("256.0.2.2").matches());
    assertFalse(IP_PATTERN.matcher("1.256.2.2").matches());
    assertFalse(IP_PATTERN.matcher("1.0.256.2").matches());
    assertFalse(IP_PATTERN.matcher("1.0.2.256").matches());
    assertFalse(IP_PATTERN.matcher("999.999.999.999").matches());
    assertFalse(IP_PATTERN.matcher("1.1.1").matches());
    assertFalse(IP_PATTERN.matcher("1.1.1.1.1").matches());
    assertFalse(IP_PATTERN.matcher(" 1.1.1.1 ").matches());
    String[] san=new String[]{"10.0.2.2","155.55.1.52","192.168.1.1","0.0.0.0","1.1.1.1","localhost","ip10.0.0.2","01.2.3.1","256.0.2.2","1.256.2.2","1.0.256.2","1.0.2.256","999.999.999.999","1.1.1","1.1.1.1.1"," 1.1.1.1 "};
    PKCS10CertificationRequest csr = CertificateUtil
            .makeCSR(TestParameters.getRSAPrivateKey1(), TestParameters.getRSAPublicKey1(),
                    "CN=www.olympus-idp.eu,O=Olympus,OU=www.olympus-project.eu,C=EU", san);
    Certificate cert = CertificateUtil.makeSelfSignedCert(TestParameters.getRSAPrivateKey1(), csr);
    // Throws exception in case of failure
    cert.verify(TestParameters.getRSAPublicKey1());
  }


}
