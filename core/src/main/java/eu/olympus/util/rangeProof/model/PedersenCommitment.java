package eu.olympus.util.rangeProof.model;

import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

/**
 * Pedersen commitment V=g^x h^(gamma)
 */
public class PedersenCommitment {
    private Group1Element g;
    private Group1Element h;
    private ZpElement gamma;
    private ZpElement number;
    private Group1Element v;

    public PedersenCommitment(Group1Element g, Group1Element h, ZpElement number, ZpElement gamma) {
        this.g = g;
        this.h = h;
        this.gamma = gamma;
        this.number = number;
        this.v=g.exp(number).mul(h.exp(gamma));
    }

    public Group1Element getG() {
        return g;
    }

    public Group1Element getH() {
        return h;
    }

    public ZpElement getGamma() {
        return gamma;
    }

    public ZpElement getNumber() {
        return number;
    }

    public Group1Element getV() {
        return v;
    }
}
