package eu.olympus.util.keyManagement;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.io.pem.PemObject;

public class KeyUtil {

  private final SecureRandom rand;

  public KeyUtil(SecureRandom rand) {
    this.rand = rand;
  }

  public String makePKCS8PemKey(PrivateKey key, String password)
      throws OperatorCreationException, IOException {
    // PKCS8 does not support any SECURE encryption algorithm. Hmpf!
    JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(
      PKCS8Generator.PBE_SHA1_RC4_128);
    encryptorBuilder.setRandom(rand);
    encryptorBuilder.setPasssword(password.toCharArray());
    OutputEncryptor encryptor = encryptorBuilder.build();
    return makePKCS8PemKey(key, encryptor);
  }

  private static String makePKCS8PemKey(PrivateKey key, OutputEncryptor encryptor)
      throws IOException {
    JcaPKCS8Generator gen = new JcaPKCS8Generator(key, encryptor);
    PemObject encodedKey = gen.generate();
    StringWriter stringWriter = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
    pemWriter.writeObject(encodedKey);
    pemWriter.close();
    stringWriter.close();
    String res = stringWriter.toString();
    return res;
  }

  public static RSAPrivateKey loadPrivatePkcs8PemKey(String keyDir, String password)
      throws Exception {
    String pemEncodedKey = new String(Files.readAllBytes(Paths.get(keyDir)));
    pemEncodedKey = pemEncodedKey.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "");
    pemEncodedKey = pemEncodedKey.replace("-----END ENCRYPTED PRIVATE KEY-----", "");
    pemEncodedKey = pemEncodedKey.replace("\n", "");
    pemEncodedKey = pemEncodedKey.replace(" ", "");
    byte[] decodedKey = Base64.decodeBase64(pemEncodedKey);
    PKCS8EncodedKeySpec keySpec = getKeySpecFromEncryptedContent(decodedKey, password);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) kf.generatePrivate(keySpec);
  }

  private static PKCS8EncodedKeySpec getKeySpecFromEncryptedContent(byte[] key, String password) throws Exception {
    EncryptedPrivateKeyInfo pkInfo = new EncryptedPrivateKeyInfo(key);
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
    SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pkInfo.getAlgName());
    return pkInfo.getKeySpec(pbeKeyFactory.generateSecret(keySpec));
  }
}
