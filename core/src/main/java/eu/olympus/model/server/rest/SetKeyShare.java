package eu.olympus.model.server.rest;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SetKeyShare {
  private int id;
  private String share;

  public SetKeyShare() {
  }

  public SetKeyShare(int id, String share) {
    this.id = id;
    this.share = share;
  }

  public int getId() {
    return id;
  }

  public void setId(int id) {
    this.id = id;
  }

  public String getShares() {
    return share;
  }

  public void setShares(String share) {
    this.share = share;
  }
}
