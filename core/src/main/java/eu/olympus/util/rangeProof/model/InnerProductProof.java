package eu.olympus.util.rangeProof.model;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.LinkedList;
import java.util.List;

/**
 * An (improved) inner product proof
 */
public class InnerProductProof {
    private List<Group1Element> l;
    private List<Group1Element> r;
    private ZpElement a;
    private ZpElement b;

    public InnerProductProof(List<Group1Element> l, List<Group1Element> r, ZpElement a, ZpElement b) {
        if(l.size()!=r.size())
            throw new IllegalArgumentException("Not matching list sizes for InnerProductProof");
        this.l = l;
        this.r = r;
        this.a = a;
        this.b = b;
    }

    public InnerProductProof(PabcSerializer.InnerProductProof protoProof) {
        this.l = new LinkedList<>();
        for(PabcSerializer.Group1Element el:protoProof.getLList())
            this.l.add(new Group1ElementBLS461(el));
        this.r= new LinkedList<>();
        for(PabcSerializer.Group1Element el:protoProof.getRList())
            this.r.add(new Group1ElementBLS461(el));
        this.a = new ZpElementBLS461(protoProof.getA());
        this.b = new ZpElementBLS461(protoProof.getB());
    }

    public List<Group1Element> getL() {
        return l;
    }


    public List<Group1Element> getR() {
        return r;
    }

    public ZpElement getA() {
        return a;
    }

    public ZpElement getB() {
        return b;
    }

    public PabcSerializer.InnerProductProof toProto() {
        List<PabcSerializer.Group1Element> protoL=new LinkedList<>();
        for (Group1Element el:this.l)
            protoL.add(el.toProto());
        List<PabcSerializer.Group1Element> protoR=new LinkedList<>();
        for (Group1Element el:this.r)
            protoR.add(el.toProto());
        return PabcSerializer.InnerProductProof.newBuilder().addAllL(protoL).addAllR(protoR)
                .setA(a.toProto()).setB(b.toProto()).build();
    }
}
