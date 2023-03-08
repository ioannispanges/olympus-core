package eu.olympus.util.rangeProof.model;

public class RangeProofBase {
    private GroupVector g;
    private GroupVector h;

    public RangeProofBase(GroupVector g, GroupVector h) {
        if(g.size()!=h.size())
            throw new IllegalArgumentException("g and h must have the same length");
        this.g = g;
        this.h = h;
    }

    public GroupVector getG() {
        return g;
    }

    public GroupVector getH() {
        return h;
    }

}
