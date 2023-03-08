package eu.olympus.model;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Holder for all shares needed by a server
 */
public class KeyShares implements Serializable {

  private final RSASharedKey rsaShare;
  private final Map<Integer, BigInteger> rsaBlindings;
  private final BigInteger oprfKey;
  private final Map<Integer, BigInteger> oprfBlindings;

  public KeyShares(RSASharedKey keyMaterial, Map<Integer, BigInteger> rsaBlindings,
      BigInteger oprfKey, Map<Integer, BigInteger> oprfBlindings) {
    this.rsaShare = keyMaterial;
    this.rsaBlindings = rsaBlindings;
    this.oprfKey = oprfKey;
    this.oprfBlindings = oprfBlindings;
  }

  public RSASharedKey getRsaShare() {
    return rsaShare;
  }

  public Map<Integer, BigInteger> getRsaBlindings() {
    return rsaBlindings;
  }

  public BigInteger getOprfKey() {
    return oprfKey;
  }

  public Map<Integer, BigInteger> getOprfBlindings() {
    return oprfBlindings;
  }

  public byte[] toBytes() {

    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    try {
      stream.write(rsaShare.getModulus().toByteArray());
      stream.write(rsaShare.getPublicExponent().toByteArray());
      stream.write(rsaShare.getPrivateKey().toByteArray());
      List<Integer> partyIds = new ArrayList<>(rsaBlindings.keySet());
      Collections.sort(partyIds);
      for (int currentId : partyIds) {
        stream.write(rsaBlindings.get(currentId).toByteArray());
      }
      stream.write(oprfKey.toByteArray());
      for (int currentId : partyIds) {
        stream.write(oprfBlindings.get(currentId).toByteArray());
      }
      stream.flush();
      return stream.toByteArray();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof KeyShares)) {
      return false;
    }
    return Arrays.equals(((KeyShares) other).toBytes(), this.toBytes());
  }
}
