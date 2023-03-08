package eu.olympus.model.server.rest;

public class AddMasterShare {
  private String newSsid;
  private String newShare;

  public AddMasterShare() {}

  public AddMasterShare(String newSsid, String newShare) {
    this.newSsid = newSsid;
    this.newShare = newShare;
  }

  public String getNewSsid() {
    return this.newSsid;
  }

  public void setNewSsid(String newSsid) {
    this.newSsid = newSsid;
  }

  public String getNewShare() {
    return newShare;
  }

  public void setNewShare(String newShare) {
    this.newShare = newShare;
  }
}
