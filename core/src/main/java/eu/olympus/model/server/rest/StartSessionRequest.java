package eu.olympus.model.server.rest;

public class StartSessionRequest {

  private String username;
  private long saltIndex;
  private String signature;
  private String token;
  private String type;

  public StartSessionRequest() {
  }

  public StartSessionRequest(String username, String token, String type, long saltIndex, String signature) {
    this.username = username;
    this.saltIndex = saltIndex;
    this.signature = signature;
    this.token = token;
    this.type = type;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public long getSaltIndex() {
    return saltIndex;
  }

  public void setSaltIndex(long saltIndex) {
    this.saltIndex = saltIndex;
  }

  public String getSignature() {
    return signature;
  }

  public void setSignature(String signature) {
    this.signature = signature;
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }
}

