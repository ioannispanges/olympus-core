package eu.olympus.util.rangeProof.model;

public class InnerProductWitness {

    private ZpVector a;
    private ZpVector b;

    public InnerProductWitness(ZpVector a, ZpVector b) {
        if(a.size()!=b.size())
            throw new IllegalArgumentException("g and h must have the same length");
        this.a = a;
        this.b = b;
    }

    public ZpVector getA() {
        return a;
    }

    public ZpVector getB() {
        return b;
    }

}

