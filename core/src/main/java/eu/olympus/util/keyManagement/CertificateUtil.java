package eu.olympus.util.keyManagement;

import eu.olympus.model.exceptions.SetupException;
import eu.olympus.model.exceptions.SigningFailedException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;

public class CertificateUtil {
  public static final String DEFAULT_TRUSTSTORE_LOCATION = System.getenv("JAVA_HOME") + "/lib/security/cacerts";
  private final KeyStore trustStore;
  private final PKIXParameters pkixParams;
  private final CertPathValidator validator;
  private final CertificateFactory x509Factory;
  private static final Pattern IP_PATTERN= Pattern.compile("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)(\\.(?!$)|$)){4}$");

  public CertificateUtil(String trustStoreDir) throws Exception {
    this(trustStoreDir, null);
  }

  /**
   * Load keystore with a password so that integrity is verified.
   */
  public CertificateUtil(String trustStoreDir, String password) throws Exception {
//     Enable OCSP verification to ensure certs have not been revoked
    System.setProperty("com.sun.net.ssl.checkRevocation", "true");
    System.setProperty("com.sun.security.enableCRLDP", "true");
    Security.setProperty("ocsp.enable", "true");
    try {
      this.trustStore = SecureStoreUtil.getSecurityStore(trustStoreDir, password);
      this.pkixParams = new PKIXParameters(trustStore);
      this.validator = CertPathValidator.getInstance("PKIX");
      this.x509Factory = CertificateFactory.getInstance("X509");
    } catch (Exception e){
      throw new SetupException("Failed to load keystore", e);
    }
  }

  public static Certificate decodePemCert(String pemEncoded) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    InputStream is = new ByteArrayInputStream(pemEncoded.getBytes());
    return certificateFactory.generateCertificate(is);
  }

  public static Certificate loadCertificate(String certificateDir) throws CertificateException, FileNotFoundException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    FileInputStream inputStream = new FileInputStream(certificateDir);
    return certificateFactory.generateCertificate(inputStream);
  }

  public static Certificate makeSelfSignedCert(RSAPrivateKey priv, PKCS10CertificationRequest csr)
      throws CertificateException {
    try {
      BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());
      String signatureAlgorithm = "SHA256WithRSA";
      ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(priv);
      Instant startDate = Instant.now();
      Instant endDate = startDate.plus(365, ChronoUnit.DAYS);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(csr.getSubjectPublicKeyInfo().getEncoded()));
      JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
          csr.getSubject(), certSerialNumber, Date.from(startDate), Date.from(endDate), csr.getSubject(), pk);
      addCAConstraints(certBuilder, pk);
      for(Attribute a: csr.getAttributes()) {
        if (org.bouncycastle.asn1.x509.Extension.subjectAlternativeName.equals(a.getAttrType())) {
            org.bouncycastle.asn1.x509.Extension bcSanExt = new org.bouncycastle.asn1.x509.Extension(
                a.getAttrType(),
                false, a.getAttributeValues()[0].toASN1Primitive().getEncoded());
            certBuilder.addExtension(bcSanExt);
        }
      }
      return new JcaX509CertificateConverter()
          .getCertificate(certBuilder.build(contentSigner));
    } catch (Exception e){
      throw new CertificateException("Failed to create signed certificate",e);
    }
  }

  private static void addCAConstraints(JcaX509v3CertificateBuilder builder, PublicKey pk)
      throws CertificateException {
    try{
      Extension basicConstraints = new BasicConstraintsExtension(true, true, Integer.MAX_VALUE);
      org.bouncycastle.asn1.x509.Extension bcBasicExt = new org.bouncycastle.asn1.x509.Extension(
          new ASN1ObjectIdentifier(basicConstraints.getId()),
          basicConstraints.isCritical(), basicConstraints.getValue());
      KeyUsageExtension keyUsage = new KeyUsageExtension();
      keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
      keyUsage.set(KeyUsageExtension.NON_REPUDIATION, true);

      org.bouncycastle.asn1.x509.Extension bcKeyUsageExt = new org.bouncycastle.asn1.x509.Extension(
          new ASN1ObjectIdentifier(keyUsage.getId()),
          keyUsage.isCritical(), keyUsage.getValue());
      Extension subjectKeyExtension = new SubjectKeyIdentifierExtension(pk.getEncoded());
      org.bouncycastle.asn1.x509.Extension bcSubjectExt = new org.bouncycastle.asn1.x509.Extension(
          new ASN1ObjectIdentifier(subjectKeyExtension.getId()),
          subjectKeyExtension.isCritical(), subjectKeyExtension.getValue());
      builder.addExtension(bcBasicExt);
      builder.addExtension(bcKeyUsageExt);
      builder.addExtension(bcSubjectExt);
    } catch (Exception e){
      throw new CertificateException("Failed to add constrains",e);
    }
  }

  public static PKCS10CertificationRequest makeCSR(RSAPrivateKey privateKey, RSAPublicKey publicKey,
      String relativeDistinguishedNames, String[] SAN) throws CertificateException  {
    try{
      String sigAlg = "SHA256WithRSA";
      Signature signature = Signature.getInstance(sigAlg);
      signature.initSign(privateKey);
      X500Name rdn = new X500Name(relativeDistinguishedNames);

      AsymmetricKeyParameter bcPublicKey = PublicKeyFactory.createKey(publicKey.getEncoded());
      SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(bcPublicKey);
      PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(rdn, keyInfo);
      csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new Time(Date.from(Instant.now())));
      ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg).build(privateKey);
      if(SAN != null) {
        GeneralName[] names = new GeneralName[SAN.length];
        for(int i = 0; i< SAN.length; i++) {
          Matcher matcher=IP_PATTERN.matcher(SAN[i]);
          if(matcher.matches())
            names[i] = new GeneralName(GeneralName.iPAddress, SAN[i]);
          else
            names[i] = new GeneralName(GeneralName.dNSName, SAN[i]);
        }
        GeneralNames gn = new GeneralNames(names);
        csrBuilder.addAttribute(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, gn);
      }
      return csrBuilder.build(contentSigner);
    } catch (Exception e){
      throw new CertificateException("Failed to construct certification request",e);
    }
  }

  public boolean verifyAndValidateCertChain(List<X509Certificate> certificateChain) {
    try {
      for (X509Certificate cert : certificateChain) {
        cert.checkValidity();
      }
      verifyCertChain(certificateChain);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public boolean verifyAndValidateCert(X509Certificate cert) {
    try {
      cert.checkValidity();
      verifySelfSigned(cert);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Verify the certificate in relation to the default truststore.
   * Note that we do not check for revoked certs since we are the one who
   * supplied the certificate to be checked!
   */
  public void verifyCertChain(List<X509Certificate> certs) throws Exception {
    try{
      CertPath path = x509Factory.generateCertPath(certs);
      pkixParams.setRevocationEnabled(true);
      validator.validate(path, pkixParams);
    } catch (Exception e){
      throw new CertificateException("Failed to verify the certificates",e);
    }
  }

  /**
   * Verify self-signed
   */
  public void verifySelfSigned(Certificate cert) throws Exception {
    try{
        CertPath path = x509Factory.generateCertPath(Arrays.asList(cert));
      // Self signed must be in the trust store so there is no revocation list to check against
      pkixParams.setRevocationEnabled(false);
      /* Validate will throw an exception on invalid chains. */
      validator.validate(path, pkixParams);
    } catch (Exception e){
      throw new CertificateException("Failed to verify the certificates",e);
    }
  }
}
