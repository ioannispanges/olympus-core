package eu.olympus.util.pairingBLS461;

import com.google.protobuf.ByteString;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingInterfaces.ZpElement;
import org.miracl.core.BLS12461.BIG;

public class ZpElementBLS461 implements ZpElement {

    BIG x;

    //public for tests, this is intended to have package visibility
    public ZpElementBLS461(BIG input){
        this.x=new BIG(input);
        this.x.mod(PairingBLS461.p);
    }

    public ZpElementBLS461(PabcSerializer.ZpElement el){
        this.x=BIG.fromBytes(el.getX().toByteArray());
    }

    @Override
    public ZpElementBLS461 add(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)el2;
        BIG res=x.plus(e.x);
        res.mod(PairingBLS461.p);
        return new ZpElementBLS461(res);
    }

    @Override
    public ZpElementBLS461 mul(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)el2;
        BIG res=BIG.modmul(x,e.x, PairingBLS461.p);
        return new ZpElementBLS461(res);
    }

    @Override
    public ZpElementBLS461 sub(ZpElement el2) {
        if(!(el2 instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)el2;
        BIG LHS = new BIG(x);
        BIG RHS = new BIG(e.x);
        // Since BIG does not support subtraction that would result in a negative value
        // we have to handle that case specially
        if (BIG.comp(LHS, RHS) < 0) {
            // First ensure that LHS and RHS are reduce mod p
            RHS.mod(PairingBLS461.p);
            LHS.mod(PairingBLS461.p);
            // Reverse the LHS and RHS to get the absolute value of the subtraction
            RHS.sub(LHS);
            BIG p = new BIG(PairingBLS461.p);
            // Finally subtract the absolute value from the modulus (p) to end up with the corect result mod p
            p.sub(RHS);
            return new ZpElementBLS461(p);
        } else {
            LHS.sub(RHS);
            LHS.mod(PairingBLS461.p);
            return new ZpElementBLS461(LHS);
        }
    }

    @Override
    public ZpElementBLS461 neg() {
        return new ZpElementBLS461(BIG.modneg(x, PairingBLS461.p));
    }

    @Override
    public ZpElement inverse() {
        BIG x=new BIG(this.x);
        x.invmodp(PairingBLS461.p);
        return new ZpElementBLS461(x);
    }

    @Override
    public boolean isUnity() {
        return x.isunity();
    }

    @Override
    public ZpElement getBit(int i) {
        int bit;
        try{
            bit=x.bit(i);
        }catch (ArrayIndexOutOfBoundsException e){
            //BIG method does not check how big the index is. Check maximum length and change for if
            bit=0;
        }
        return new ZpElementBLS461(new BIG(bit));
    }

    @Override
    public PabcSerializer.ZpElement toProto() {
        byte[] valueX=new byte[PairingBLS461.FIELD_BYTES];
        x.toBytes(valueX);
        return PabcSerializer.ZpElement.newBuilder()
                .setX(ByteString.copyFrom(valueX))
                .build();
    }

    @Override
    public byte[] toBytes() {
        return bigToBytes(x);
    }

    @Override
    public int getNBits() {
        return x.nbits();
    }

    @Override
    public ZpElement pow(int i) {
        return new ZpElementBLS461(x.powmod(new BIG(i),PairingBLS461.p));
    }

    private static byte[] bigToBytes(BIG big) {
        byte[] ret = new byte[PairingBLS461.FIELD_BYTES];
        big.toBytes(ret);
        return ret;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZpElementBLS461 that = (ZpElementBLS461) o;
        return (BIG.comp(x,that.x)==0);
    }

    @Override
    public String toString() {
        return x.toString();
    }
}
