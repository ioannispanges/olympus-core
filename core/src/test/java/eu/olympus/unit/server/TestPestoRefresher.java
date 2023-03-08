package eu.olympus.unit.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.PestoRefresher;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.util.CommonCrypto;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

public class TestPestoRefresher {
  // Modulus 7727 * 7741 =  59814707
  private static final BigInteger n = new BigInteger("59814707");
  // e = 17
  private static final BigInteger e = new BigInteger("17");
  // d = 49246433 = 1+2+49246430
  private static final BigInteger d = new BigInteger("49246433");

  private PestoRefresher refresher0, refresher1, refresher2;
  private BigInteger key0, key1, key2;
  private Map<Integer, BigInteger> blindings0, blindings1, blindings2;
  private Method updateOprfShare;
  private Method updateRsaShare;

  @Before
  public void setup() throws Exception {
    key0 = new BigInteger("49246430");
    blindings0 = new HashMap<>();
    blindings0.put(1, new BigInteger("10")); // key 0,1 <-> 1,0
    blindings0.put(2, new BigInteger("20")); // key 0,2 <-> 2,0

    key1 = new BigInteger("1");
    blindings1 = new HashMap<>();
    blindings1.put(0, new BigInteger("10")); // key 1,0 <-> 0,1
    blindings1.put(2, new BigInteger("21")); // key 1,2 <-> 2,1

    key2 = new BigInteger("2");
    blindings2 = new HashMap<>();
    blindings2.put(0, new BigInteger("20")); // key 2,0 <-> 0,2
    blindings2.put(1, new BigInteger("21")); // key 2,1 <-> 1,2

    refresher0 = new PestoRefresher(0, new SoftwareServerCryptoModule(new Random(1)));
    refresher1 = new PestoRefresher(1, new SoftwareServerCryptoModule(new Random(2)));
    refresher2 = new PestoRefresher(2, new SoftwareServerCryptoModule(new Random(3)));

    updateOprfShare = PestoRefresher.class.
        getDeclaredMethod("updateOprfShare", BigInteger.class, Map.class, byte[].class, String.class);
    updateOprfShare.setAccessible(true);
    updateRsaShare = PestoRefresher.class.
        getDeclaredMethod("updateRsaShare", RSASharedKey.class, Map.class, byte[].class, String.class);
    updateRsaShare.setAccessible(true);
  }

  @Test
  public void testOprfSsid() throws Exception {
    BigInteger updated0 = (BigInteger)
        updateOprfShare.invoke(refresher0, key0, blindings0, "tst".getBytes(), "salt");
    BigInteger updated1 = (BigInteger)
        updateOprfShare.invoke(refresher1, key1, blindings1, "test".getBytes(), "salt");
    BigInteger updated2 = (BigInteger)
        updateOprfShare.invoke(refresher2, key2, blindings2, "test".getBytes(), "salt");
    assertNotEquals(updated0.add(updated1).add(updated2), key0.add(key1).add(key2));

    updated0 = (BigInteger)
        updateOprfShare.invoke(refresher0, key0, blindings0, "test".getBytes(), "salt");
    updated1 = (BigInteger)
        updateOprfShare.invoke(refresher1, key1, blindings1, "test".getBytes(), "salt");
    updated2 = (BigInteger)
        updateOprfShare.invoke(refresher2, key2, blindings2, "test".getBytes(), "slt");
    assertNotEquals(updated0.add(updated1).add(updated2), key0.add(key1).add(key2));
  }

  @Test
  public void testUpdatedOprfShares() throws Exception {
    BigInteger updated0 = (BigInteger)
        updateOprfShare.invoke(refresher0, key0, blindings0, "test".getBytes(), "salt");
    BigInteger updated1 = (BigInteger)
        updateOprfShare.invoke(refresher1, key1, blindings1, "test".getBytes(), "salt");
    BigInteger updated2 = (BigInteger)
        updateOprfShare.invoke(refresher2, key2, blindings2, "test".getBytes(), "salt");
    assertEquals(updated0.add(updated1).add(updated2).mod(CommonCrypto.CURVE_ORDER), key0.add(key1).add(key2).mod(CommonCrypto.CURVE_ORDER));
    // Sanity checks
    assertNotEquals(updated0, updated1);
    assertNotEquals(updated1, updated2);
    assertNotEquals(updated0, updated2);
    // Check that all updates are actually large numbers (as expected)
    assertTrue(updated0.abs().compareTo(new BigInteger("1000")) == 1);
    assertTrue(updated1.abs().compareTo(new BigInteger("1000")) == 1);
    assertTrue(updated2.abs().compareTo(new BigInteger("1000")) == 1);
  }

  @Test
  public void testUpdatedRSAShares() throws Exception {
    BigInteger updated0 = (BigInteger)
        updateRsaShare.invoke(refresher0, new RSASharedKey(n, key0, e),
            blindings0, "test".getBytes(), "salt");
    BigInteger updated1 = (BigInteger)
        updateRsaShare.invoke(refresher1, new RSASharedKey(n, key1, e),
            blindings1, "test".getBytes(), "salt");
    BigInteger updated2 = (BigInteger)
        updateRsaShare.invoke(refresher2, new RSASharedKey(n, key2, e),
            blindings2, "test".getBytes(), "salt");
    assertEquals(updated0.add(updated1).add(updated2), key0.add(key1).add(key2));

    // Sanity checks
    assertNotEquals(updated0, updated1);
    assertNotEquals(updated1, updated2);
    assertNotEquals(updated0, updated2);
    // Check that all updates are actually large numbers (as expected)
    assertTrue(updated0.abs().compareTo(new BigInteger("1000")) == 1);
    assertTrue(updated1.abs().compareTo(new BigInteger("1000")) == 1);
    assertTrue(updated2.abs().compareTo(new BigInteger("1000")) == 1);
  }

  @Test
  public void testCombineSsids() {
    List<String> vals = new ArrayList<>();
    vals.add(Base64.encodeBase64String(new byte[] {1}));
    vals.add(Base64.encodeBase64String(new byte[] {2}));
    byte[] res = refresher0.combineSsids(vals);
    assertNotEquals(res.toString(), Base64.encodeBase64String(new byte[] {1}));
    assertNotEquals(res.toString(), Base64.encodeBase64String(new byte[] {2}));

    vals = new ArrayList<>();
    vals.add(Base64.encodeBase64String(new byte[] {2}));
    vals.add(Base64.encodeBase64String(new byte[] {2}));
    vals.add(Base64.encodeBase64String(new byte[] {2}));
    res = refresher0.combineSsids(vals);
    assertEquals(res[0], 2);
  }

  @Test
  public void testSharing() {
    KeyShares master = new KeyShares(new RSASharedKey(n, key0, e), blindings0, key1, blindings0);
    List<byte[]> shares = refresher0.reshareMasterKeys(master, 3);
    // Sanity checks
    assertNotEquals(master.toBytes(), shares.get(0));
    assertNotEquals(master.toBytes(), shares.get(1));
    assertNotEquals(master.toBytes(), shares.get(2));
    assertNotEquals(shares.get(0), shares.get(1));
    assertNotEquals(shares.get(0), shares.get(2));
    assertNotEquals(shares.get(1), shares.get(2));

    // Check that the shares can be restored
    KeyShares newMaster = refresher0.combineMasterShares(shares);
    assertTrue(master.equals(newMaster));
  }

  @Test(expected = RuntimeException.class)
  public void testCombineMasterKeysException() {
	  refresher0.combineMasterShares(Arrays.asList(new byte[] {0x00,0x12, 0x13}));
	  fail();
  }
  
  @Test(expected = RuntimeException.class)
  public void testGetGeneratorExceptions() {
	  Map<Integer, BigInteger> customBlindings = new HashMap<>();
	  customBlindings.put(0, null);
	  customBlindings.put(1, null);
	  customBlindings.put(2, null);
    KeyShares master = new KeyShares(new RSASharedKey(n, key0, e), customBlindings, key1, blindings0);
    refresher0.updateSharesFromMaster(new byte[] {0x12, 0x34, 0x56}, master);
    fail("Exception should have occured");
  }
}
