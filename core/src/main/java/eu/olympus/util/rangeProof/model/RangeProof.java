package eu.olympus.util.rangeProof.model;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

/**
 * A range proof
 */
public class RangeProof {

    private Group1Element t1;
    private Group1Element t2;
    private ZpElement tauX;
    private ZpElement mu;
    private ZpElement tHat;
    private Group1Element a;
    private Group1Element s;
    private InnerProductProof innerProductProof;

    public RangeProof(Group1Element t1, Group1Element t2, ZpElement tauX, ZpElement mu, ZpElement tHat, Group1Element a, Group1Element s, InnerProductProof innerProductProof) {
        this.t1 = t1;
        this.t2 = t2;
        this.tauX = tauX;
        this.mu = mu;
        this.tHat = tHat;
        this.a = a;
        this.s = s;
        this.innerProductProof = innerProductProof;
    }

    public RangeProof(PabcSerializer.RangeProof protoProof) {
        this.t1 = new Group1ElementBLS461(protoProof.getT1());
        this.t2 = new Group1ElementBLS461(protoProof.getT2());
        this.tauX = new ZpElementBLS461(protoProof.getTauX());
        this.mu = new ZpElementBLS461(protoProof.getMu());
        this.tHat = new ZpElementBLS461(protoProof.getTHat());
        this.a =new Group1ElementBLS461(protoProof.getA());
        this.s = new Group1ElementBLS461(protoProof.getS());
        this.innerProductProof = new InnerProductProof(protoProof.getInnerProductProof());
    }

    public Group1Element getT1() {
        return t1;
    }

    public Group1Element getT2() {
        return t2;
    }

    public ZpElement getTauX() {
        return tauX;
    }

    public ZpElement getMu() {
        return mu;
    }

    public ZpElement gettHat() {
        return tHat;
    }

    public Group1Element getA() {
        return a;
    }

    public Group1Element getS() {
        return s;
    }

    public InnerProductProof getInnerProductProof() {
        return innerProductProof;
    }

    public PabcSerializer.RangeProof toProto() {
        return PabcSerializer.RangeProof.newBuilder().setT1(t1.toProto()).setT2(t2.toProto()).setTauX(tauX.toProto()).setMu(mu.toProto())
                .setTHat(tHat.toProto()).setA(a.toProto()).setS(s.toProto()).setInnerProductProof(innerProductProof.toProto()).build();
    }
}
