package eu.olympus.util.keyManagement;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;

public class SecureStoreUtil {

  public static KeyStore getEmptySecurityStore() throws Exception {
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(null, null);
    return ks;
  }

  public static KeyStore getSecurityStore(String storeDir, String password) throws Exception {
    KeyStore keystore = KeyStore.getInstance("JKS");
    InputStream is = Files.newInputStream(Paths.get(storeDir));
    // Assume that we are using the default password for the truststore
    if (password != null) {
      keystore.load(is, password.toCharArray());
    } else {
      keystore.load(is, null);
    }
    is.close();
    return keystore;
  }

  public static void writeSecurityStore(KeyStore store, String password, String storeDir) throws Exception {
    Path path = Paths.get(storeDir);
    Files.createDirectories(path.getParent());
    OutputStream os = Files.newOutputStream(path);
    store.store(os, password.toCharArray());
    os.close();
  }

  public static void writeCertificateToStore(String certName, String certDir,
      String trustStoreDir, String trustStorePassword) throws Exception {
    KeyStore keyStore = getSecurityStore(trustStoreDir, trustStorePassword);
    keyStore.setCertificateEntry(certName, CertificateUtil.loadCertificate(certDir));
    writeSecurityStore(keyStore, trustStorePassword, trustStoreDir);
  }

  public static void writeKeyToStore(String keyName, String pemPkcs8KeyDir, String publicKeyCertDir,
      String keyStoreDir, String keyStorePassword, String keyPassword) throws Exception {
    KeyStore keyStore = getSecurityStore(keyStoreDir, keyStorePassword);
    RSAPrivateKey privateKey = KeyUtil.loadPrivatePkcs8PemKey(pemPkcs8KeyDir, keyPassword);
    Certificate certificate = CertificateUtil.loadCertificate(publicKeyCertDir);
    keyStore.setKeyEntry(keyName, privateKey, keyPassword.toCharArray(), new Certificate[] {certificate});
    keyStore.setCertificateEntry(keyName + "-certificate", certificate);
    writeSecurityStore(keyStore, keyStorePassword, keyStoreDir);
  }

}
