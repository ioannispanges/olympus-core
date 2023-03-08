package eu.olympus.server;

import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.util.CommonCrypto;
import eu.olympus.util.Util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.Charsets;
import org.bouncycastle.util.encoders.Base64;

public  class PestoRefresher {
  private final int myId;
  private final ServerCryptoModule crypto;

  public PestoRefresher(int myId, ServerCryptoModule crypto) {
    this.myId = myId;
    this.crypto = crypto;
  }

  /**
   * Deterministically compute updated key shares based on a master set of KeyShares using an SSID
   */
  public KeyShares updateSharesFromMaster(byte[] ssid, KeyShares masterShares) {
    Map<Integer, BigInteger> oldRsaBlindings = masterShares.getRsaBlindings();
    BigInteger updatedPrivateKey = updateRsaShare(masterShares.getRsaShare(), masterShares.getRsaBlindings(), ssid, "d-value");
    RSASharedKey newRsaKey = new RSASharedKey(masterShares.getRsaShare().getModulus(), updatedPrivateKey, masterShares.getRsaShare().getPublicExponent());

    // Then compute updated RSA blindings
    Map<Integer, BigInteger> newRsaBlindings = new HashMap<>();
    for (int currentId : oldRsaBlindings.keySet()) {
      newRsaBlindings.put(currentId,
          computeRandomRefresh(oldRsaBlindings.get(currentId), ssid, Math.min(currentId, myId), "rsa-blindings",
              CommonCrypto.COMPUTATION_SEC_BYTES * 8));
    }

    Map<Integer, BigInteger> oldOprfBlindings = masterShares.getOprfBlindings();
    BigInteger updatedOprfShare = updateOprfShare(masterShares.getOprfKey(), oldOprfBlindings, ssid, "k-value");

    // Then compute updated oprf blindings
    Map<Integer, BigInteger> newOprfBlindings = new HashMap<>();
    for (int currentId : oldOprfBlindings.keySet()) {
      newOprfBlindings.put(currentId,
          computeRandomRefresh(oldOprfBlindings.get(currentId), ssid, currentId, "update-val",
              CommonCrypto.COMPUTATION_SEC_BYTES * 8));
    }
    return new KeyShares(newRsaKey, newRsaBlindings, updatedOprfShare, newOprfBlindings);
  }

  private BigInteger updateRsaShare(RSASharedKey rsaKey, Map<Integer, BigInteger> rsaBlindings, byte[] ssid, String salt) {
    BigInteger newd = rsaKey.getPrivateKey();
    BigInteger n = rsaKey.getModulus();

    for (int currentId : rsaBlindings.keySet()) {
      // The amount of bits used to represent the amount of parties
      int bitNumberParties = (int) Math.ceil(Math.log(rsaBlindings.keySet().size() +1)/Math.log(2));
      int sizeOfPadding = 2*bitNumberParties + 8*2*crypto.STATISTICAL_SEC_BYTES + n.bitLength();
      BigInteger padding = computeRandomRefresh(rsaBlindings.get(currentId), ssid, currentId, salt, sizeOfPadding);
      // Finally pick a bit to decide if the padding should be positive or negative
      if (computeRandomRefreshBit(rsaBlindings.get(currentId), ssid, currentId, salt)) {
        padding = padding.negate();
      }
      newd = myId > currentId ? newd.add(padding) : newd.subtract(padding);
    }
    return newd;
  }

  private BigInteger updateOprfShare(BigInteger oprfKey, Map<Integer, BigInteger> oprfBlindings, byte[] ssid, String salt) {
    BigInteger newOprfKey = oprfKey;
    for (int currentId : oprfBlindings.keySet()) {
      BigInteger padding = computeRandomRefresh(oprfBlindings.get(currentId), ssid, currentId, salt, CommonCrypto.BITS_IN_GROUP+8*CommonCrypto.STATISTICAL_SEC_BYTES).mod(CommonCrypto.CURVE_ORDER);
      newOprfKey = myId > currentId ? newOprfKey.add(padding).mod(CommonCrypto.CURVE_ORDER) : newOprfKey.subtract(padding).mod(CommonCrypto.CURVE_ORDER);
    }
    return newOprfKey;
  }

  private BigInteger computeRandomRefresh(BigInteger oldVal, byte[] ssid, int id, String salt, int sizeInBits) {
    SecureRandom gen = getGenerator(oldVal, ssid, id, salt);
    return new BigInteger(sizeInBits, gen);
  }

  private boolean computeRandomRefreshBit(BigInteger oldVal, byte[] ssid, int id, String salt) {
    return getGenerator(oldVal, ssid, id, salt).nextBoolean();
  }

  private SecureRandom getGenerator(BigInteger oldVal, byte[] ssid, int id, String salt) {
    try {
      // ID is always the lowest of the IDs in the pair of servers holding the blinding to ensure the same ID for both servers
      int currentId = Math.min(id, myId);
      byte[] currentIdBytes = ByteBuffer.allocate(4).putInt(currentId).array();
      byte[] seed = crypto.hashList(Arrays.asList(ssid, oldVal.toByteArray(), currentIdBytes, salt.getBytes(Charsets.UTF_8)));
      SecureRandom secure = SecureRandom.getInstance("SHA1PRNG"); //Seems to be the only alg?
      secure.setSeed(seed);
      return secure;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Combine the list of SSID from each partial IdP, using XOR
   */
  public byte[] combineSsids(List<String> ssids) {
    byte[] ssid = Base64.decode(ssids.remove(0));
    for (String currentSsid : ssids) {
      ssid = Util.xorArray(ssid, Base64.decode(currentSsid));
    }
    return ssid;
  }

  /**
   * Reshare the master keys using XOR sharing
   */
  public List<byte[]> reshareMasterKeys(KeyShares masterShares, int amount) {
    List<byte[]> res = new ArrayList<>(amount);
    byte[] masterShareBytes = toByteArray(masterShares);
    int length = masterShareBytes.length;
    byte[] incrementalPadding = new byte[length];
    for (int i = 0; i < amount - 1; i++) {
      byte[] currentPadding = crypto.getBytes(length);
      res.add(currentPadding);
      incrementalPadding = Util.xorArray(currentPadding, incrementalPadding);
    }
    // Compute the last share
    byte[] finalShare = Util.xorArray(masterShareBytes, incrementalPadding);
    res.add(finalShare);
    return res;
  }

  private byte[] toByteArray(Object input) {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    ObjectOutputStream out = null;
    try {
      out = new ObjectOutputStream(bos);
      out.writeObject(input);
      out.flush();
      return bos.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException(e);
    } finally {
      try {
        bos.close();
      } catch (IOException e) {
        // Ignore issues with closing
      }
    }
  }

  public KeyShares combineMasterShares(List<byte[]> shares) {
    byte[] incrementalPadding = new byte[shares.get(0).length];
    for (byte[] share : shares) {
      incrementalPadding = Util.xorArray(share, incrementalPadding);
    }
    return (KeyShares) fromByteArray(incrementalPadding);
  }

  private Object fromByteArray(byte[] input) {
    ByteArrayInputStream bis = new ByteArrayInputStream(input);
    try (ObjectInput in = new ObjectInputStream(bis)) {
      return in.readObject();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    // Ignore issues with closing
  }
}
