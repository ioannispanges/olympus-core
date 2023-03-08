package eu.olympus.unit.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import eu.olympus.TestParameters;
import eu.olympus.util.SoftwareCommonCrypto;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;

public class TestSoftwareCommonCrypto {
  @Rule
  public final ExpectedException exception = ExpectedException.none();

  SoftwareCommonCrypto crypto = new SoftwareCommonCrypto(new Random(0)) {
    @Override
    public BigInteger getModulus() {
      return modulus;
    }
  };
  private final BigInteger modulus = new BigInteger("1692653793237283178"
      + "02095979470165564762540986145283170380070329250448153326949"
      + "02620941127722957895783030645359332697065350909516256222749"
      + "39954786381642292178998250679033136907201643648185142250141"
      + "57779435918374097259509906191697335879160010473715585561329"
      + "17730028100298823236433259405983281664568650475598367869076"
      + "30285969138714777606722811345389631922951468015303013611718"
      + "46218097014429092089680883412967387138413337923553586431481"
      + "57170767560339357020918008852864926335997159916869547088339"
      + "14319460219856455867125987074077998909016307802570248407193"
      + "03331855604730713974984313369625580744252999429176146016735"
      + "83116227");
  private final BigInteger exponent = new BigInteger("65537");

  @Test
  public void testGetStandardRSAKey() throws Exception {
    RSAPublicKey pk = (RSAPublicKey)crypto.getStandardRSAkey();
    assertEquals(exponent, pk.getPublicExponent());
    assertEquals(modulus, pk.getModulus());
  }

  @Test
  public void testHash() throws Exception {
    byte[] val = "value1".getBytes();
    byte[] hash = crypto.hashSingleElement(val);
    MessageDigest md = MessageDigest.getInstance("SHA-512");
    md.update(val);
    byte[] h2 = md.digest();
    assertEquals(b64(hash), b64(h2));
  }

  @Test
  public void testHashList() throws Exception {
    List<byte[]> values = new ArrayList<byte[]>();
    values.add("value1".getBytes());
    values.add("value2".getBytes());
    byte[] hash = crypto.hashList(values);
    MessageDigest md = MessageDigest.getInstance("SHA-512");
    md.update(values.get(0));
    byte[] digest1 = md.digest();
    md.reset();
    md.update(values.get(1));
    byte[] digest2 = md.digest();
    md.reset();
    md.update(digest1);
    md.update(digest2);
    byte[] h2 = md.digest();
    assertEquals(b64(hash), b64(h2));
  }

  @Test
  public void verifyRSASignaure() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
    PublicKey publicKey = kf.generatePublic(pubSpec);
    byte[] message = "salt".getBytes();

    String signature = "QOinQODAyRMOheMq2i4uX2ICCwRU46FI3Das/Co+SURlWffpyGWs6vmMe4VTuTku3HJAVxQ2mM6"
        + "/hx+ubd7JcnyYItGar4YvN4DdH/hhs9N8bE2DHJIKexAPQ+dnaqSrtW+ZaHM5WjWcL1v/30K7zanRYz+14ah3K0n"
        + "FAIjJnRXPfT3nQsnvwanvAxE9CqVA1xcHyjtPPUzdTn+IwW7eU004VGyeZwKz6dyHEFbZyNvlF13tdCMD/6P/415"
        + "tRyzqIGaStev7tLpeqViX/0s1p0npdomcKS/5QlSAgP+Cd8m11h5ZQUFLFEGNYGS004yuoJ8QT7bPOWz+yDfRcPQ"
        + "dKg==";

    boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));

    assertTrue(valid);
  }

  @Test
  public void verifyECSignaure() throws Exception {
    List<byte[]> message = new ArrayList<byte[]>();
    message.add("salt".getBytes());
    message.add("M1".getBytes());

    String signature = "MEYCIQCYWHeRr0ax61I2tCF2ccqJooZeLne9Dx1e7iMPWJqe1gIhANfxHiG5mY0eKRrIb8mAc/U"
        + "V3TRbwVTq9zRJoEDquqhX";

    boolean valid = crypto.verifySignature(TestParameters.getECPublicKey1(),
        message, Base64.decodeBase64(signature));

    assertTrue(valid);
  }

  @Test
  public void verifySignatureException() throws Exception {
    PublicKey publicKey = null;

    List<byte[]> message = new ArrayList<byte[]>();
    message.add("salt".getBytes());
    message.add("M1".getBytes());


    String signature = "KPWUAxTpHWNYzsR3p5FggGSdMCvl2fOgB8Peep2"
        + "ICXPU72K0LGIAxn79jTWFcWjnA0HQRrOMHKZO+K93WkEU27gDA4lOK/"
        + "0nVGjqa+9eofOcobqONT2f/3jemZFAvh/OUMLT0JRtbQKb6IIWsEsZX"
        + "TSvdOcMP/bVF8yjVTKs8nrhg8DsWHJxOq3XD4/8gxDrTwAguz7AMXnh"
        + "CxOZ0k9N/l0z+SICyzR5bKUw6ZXD/4S4Iwl7J4fAMZ2TPxHVX+/7NM8"
        + "TqW6o6pGcNSwPklTzcl0W1+yt5HYhK31n92ATvNcWbVnEpEIjrkS6cY"
        + "2zIkjd7/OWqZEN7pK6IJlu+taC9A==";

    boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
    assertFalse(valid);
  }

  @Test
  public void verifyBadSignaure() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
    PublicKey publicKey = kf.generatePublic(pubSpec);
    List<byte[]> message = new ArrayList<byte[]>();
    message.add("salt".getBytes());
    message.add("M1".getBytes());


    String signature = "KPWUAxTpHWNYzsR3p5FggGSdMCvl2fOgB8Peep2"
        + "ICXPU72K0LGIAxn79jTWFcWjnA0HQRrOMHKZO+K93WkEU27gDA4lOK/"
        + "0nVGjqa+9eofOcobqONT2f/3jemZFAvh/OUMLT0JRtbQKb6IIWsEsZX"
        + "TSvdOcMP/bVF8yjVTKs8nrhg8DsWHJxOq3XD4/8gxDrTwAguz7AMXnh"
        + "CxOZ0k9N/l0z+SICyzR5bKUw6ZXD/4S4Iwl7J4fAMZ2TPxHVX+/7NM8"
        + "TqW6o6pGcNSwPklTzcl0W1+yt5HYhK31n92ATvNcWbVnEpEIjrkS6cY"
        + "2zIkjd7/OWqZEN7pK6IJlu+taB9A==";

    boolean valid = crypto.verifySignature(publicKey, message, Base64.decodeBase64(signature));
    assertFalse(valid);
  }

  @Test
  public void testGetBytes() {
    assertEquals(32, crypto.getBytes(32).length);
    assertEquals(1, crypto.getBytes(1).length);
    assertEquals(256, crypto.getBytes(256).length);
    assertEquals(257, crypto.getBytes(257).length);
  }

  @Test
  public void testHashToGroupElement() {
    ECP ecp = crypto.hashToGroup1Element("inputValue".getBytes());

    byte[] bytes = new byte[117];
    ecp.toBytes(bytes, false);
    String expected = "BAwmBOJCKqWGfmPLQ2YsZ7B/xbKh0usSQuwPGfaQIdVVxxXlm" +
        "zoIK1+AJ6VcygGK9HCFsKn+TG1Z4REM3oYHao+Be6c8aSrBLWZHHOZ3vEka" +
        "hnUHjXca41HTvOabrym0KzV/BX5gs98YqdJSbVT+O/HgGwi4";
    assertEquals(expected, b64(bytes));
  }

  @Test
  public void testConstructNonce() throws Exception {
    byte[] nonce1 = crypto.constructNonce("user1", 1000);
    byte[] nonce2 = crypto.constructNonce("user1", 1000);
    byte[] nonce3 = crypto.constructNonce("user2", 1000);
    byte[] nonce4 = crypto.constructNonce("user1", 2000);
    assertEquals(b64(nonce1), b64(nonce2));
    assertNotEquals(b64(nonce2), b64(nonce3));
    assertNotEquals(b64(nonce2), b64(nonce4));
  }

  @Test
  public void testGetRandomNumer() {
    BIG rnd = crypto.getRandomNumber();
    assertThat(rnd, IsInstanceOf.instanceOf(BIG.class));
  }


  @Test
  public void hashToIntegerTest() throws Exception {
    BigInteger bigInteger = crypto.hashToBigInteger(Arrays.asList("bytes".getBytes(), "salt".getBytes()), modulus);
    // Verify less than modulus
    assertTrue(bigInteger.compareTo(modulus) < 0);
    // Verify that the number is still very big
    assertTrue(bigInteger.compareTo(modulus.shiftRight(20)) > 0);
    BigInteger otherBigInteger = crypto.hashToBigInteger(Arrays.asList("bytes2".getBytes(), "salt".getBytes()), modulus);
    BigInteger twoPower = BigInteger.ONE.shiftLeft(512);
    // Verify that the smallest and largest parts are distinct
    assertNotEquals(otherBigInteger.mod(twoPower), bigInteger.mod(twoPower));
    assertNotEquals(otherBigInteger.shiftRight(1900), bigInteger.shiftRight(1900));
    BigInteger otherSalt = crypto.hashToBigInteger(Arrays.asList("bytes".getBytes(), "salt2".getBytes()), modulus);
    // Verify that the smallest and largest parts are distinct
    assertNotEquals(otherSalt.mod(twoPower), bigInteger.mod(twoPower));
    assertNotEquals(otherSalt.shiftRight(1900), bigInteger.shiftRight(1900));
  }

  private String b64(byte[] input) {
    return Base64.encodeBase64String(input);
  }
}
