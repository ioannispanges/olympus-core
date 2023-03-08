package eu.olympus.util.pairingBLS461;

import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import org.miracl.core.BLS12461.FP12;

public class Group3ElementBLS461 implements Group3Element {
    FP12 x;

    public Group3ElementBLS461(FP12 x){
        this.x=x;//Copy?
    }

    public Group3ElementBLS461 mul(Group3Element el2) {
        if(!(el2 instanceof Group3ElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group3ElementBLS461 e2=(Group3ElementBLS461)el2;
        Group3ElementBLS461 res=new Group3ElementBLS461(new FP12(x));
        res.x.mul(e2.x);
        return res;
    }

    @Override
    public Group3ElementBLS461 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        // pow supposedly consumes too much RAM. However, every exponentiation
        // can be made over Group2 (or 2), because of pairing properties, as reflected on D4.1
        return new Group3ElementBLS461(x.pow(e.x));
    }

    @Override
    public Group3Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return this.exp(e.neg());
    }

    @Override
    public boolean isUnity() {
        return x.isunity();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group3ElementBLS461 that = (Group3ElementBLS461) o;
        return x.equals(that.x);
    }
}
