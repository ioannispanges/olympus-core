package eu.olympus.model.server.rest;

import eu.olympus.model.SerializedKey;

public class KeyAndCert {
  private SerializedKey privKey;
  private String certificate;

  public KeyAndCert() {}

  public KeyAndCert(SerializedKey privKey, String certificate) {
    this.privKey = privKey;
    this.certificate = certificate;
  }

  public SerializedKey getPrivKey() {
    return privKey;
  }

  public void setPrivKey(SerializedKey privKey) {
    this.privKey = privKey;
  }

  public String getCertificate() {
    return certificate;
  }

  public void setCertificate(String certificate) {
    this.certificate = certificate;
  }

}
