package eu.olympus.util.pairingBLS461;

import com.google.protobuf.ByteString;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.PAIR;

public class Group1ElementBLS461 implements Group1Element {

    ECP x;

    public Group1ElementBLS461(ECP x){
        this.x=x; //Copy?
    }

    public Group1ElementBLS461(PabcSerializer.Group1Element x)
    {
        this.x=convertFromProto(x.getX());
    }

    @Override
    public Group1ElementBLS461 mul(Group1Element el2) {
        if(!(el2 instanceof Group1ElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group1ElementBLS461 e2=(Group1ElementBLS461)el2;
        Group1ElementBLS461 res=new Group1ElementBLS461(new ECP(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group1ElementBLS461 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return new Group1ElementBLS461(PAIR.G1mul(x,e.x));
    }

    @Override
    public Group1Element invExp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return this.exp(e.neg());
    }

    @Override
    public boolean isUnity() {
        return x.is_infinity(); //I think this is correct as it is the neutral element in addition (that we represent as multiplication).
    }

    @Override
    public PabcSerializer.Group1Element toProto() {
        return PabcSerializer.Group1Element.newBuilder()
                .setX(convertToProto(x))
                .build();
    }

    @Override
    public Group1Element multiExp(Group1Element[] elements, ZpElement[] exponents) {
        if (elements.length!=exponents.length)
            throw new IllegalArgumentException("Not matching lengths");
        int n=elements.length;
        if (n==0)
            throw new IllegalArgumentException("Empty arrays");
        ECP[] bases=new ECP[n];
        for(int i=0;i<n;i++){
            if(!(elements[i] instanceof Group1ElementBLS461))
                throw new IllegalArgumentException("Elements must be of the same type");
            bases[i]=((Group1ElementBLS461)elements[i]).x;
        }
        BIG[] exp=new BIG[n];
        for(int i=0;i<n;i++){
            if(!(exponents[i] instanceof ZpElementBLS461))
                throw new IllegalArgumentException("Elements must be of the same type");
            exp[i]=((ZpElementBLS461)exponents[i]).x;
        }
        return new Group1ElementBLS461(x.muln(n,bases,exp));
    }

    @Override
    public byte[] toBytes() {
        return ecpToBytes(x);
    }

    private static byte[] ecpToBytes(ECP e) {
        byte[] ret = new byte[2 * PairingBLS461.FIELD_BYTES + 1];
        e.toBytes(ret, false);
        return ret;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group1ElementBLS461 that = (Group1ElementBLS461) o;
        return x.equals(that.x);
    }

    private static PabcSerializer.ECP convertToProto(ECP x){
        byte[] valueX = new byte[PairingBLS461.FIELD_BYTES];
        byte[] valueY = new byte[PairingBLS461.FIELD_BYTES];
        x.getX().toBytes(valueX);
        x.getY().toBytes(valueY);
        return PabcSerializer.ECP.newBuilder()
                .setX(ByteString.copyFrom(valueX))
                .setY(ByteString.copyFrom(valueY))
                .build();
    }

    private static ECP convertFromProto(PabcSerializer.ECP w) {
        byte[] valueX = w.getX().toByteArray();
        byte[] valueY = w.getY().toByteArray();
        return new ECP(BIG.fromBytes(valueX), BIG.fromBytes(valueY));
    }

}
