package eu.olympus.util.rangeProof.model;

import eu.olympus.util.pairingInterfaces.Group1Element;

public class InnerProductBase {
    private GroupVector g;
    private GroupVector h;
    private Group1Element u;

    public InnerProductBase(GroupVector g, GroupVector h, Group1Element u) {
        if(g.size()!=h.size())
            throw new IllegalArgumentException("g and h must have the same length");
        this.g = g;
        this.h = h;
        this.u = u;
    }

    public GroupVector getG() {
        return g;
    }


    public GroupVector getH() {
        return h;
    }


    public Group1Element getU() {
        return u;
    }

}
