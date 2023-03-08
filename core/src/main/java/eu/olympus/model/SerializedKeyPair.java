package eu.olympus.model;

public class SerializedKeyPair {
	private SerializedKey publicKey;
	private SerializedKey privateKey;

	public SerializedKeyPair() {
	}
	
	public SerializedKeyPair(SerializedKey publicKey, SerializedKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public SerializedKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(SerializedKey publicKey) {
		this.publicKey = publicKey;
	}

	public SerializedKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(SerializedKey privateKey) {
		this.privateKey = privateKey;
	}
	
}
