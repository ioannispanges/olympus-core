package eu.olympus.util.pairingBLS461;

import com.google.protobuf.ByteString;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ECP2;
import org.miracl.core.BLS12461.FP2;
import org.miracl.core.BLS12461.PAIR;

public class Group2ElementBLS461 implements Group2Element {

    ECP2 x;

    public Group2ElementBLS461(ECP2 x){
        this.x=x;//Copy?
    }

    public Group2ElementBLS461(PabcSerializer.Group2Element x){
        this.x=transformFromProto(x.getX());//Copy?
    }

    @Override
    public Group2ElementBLS461 mul(Group2Element el2) {
        if(!(el2 instanceof Group2ElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        Group2ElementBLS461 e2=(Group2ElementBLS461)el2;
        Group2ElementBLS461 res=new Group2ElementBLS461(new ECP2(x));
        res.x.add(e2.x);
        return res;
    }

    @Override
    public Group2ElementBLS461 exp(ZpElement exp) {
        if(!(exp instanceof ZpElementBLS461))
            throw new IllegalArgumentException("Elements must be of the same type");
        ZpElementBLS461 e=(ZpElementBLS461)exp;
        return new Group2ElementBLS461(PAIR.G2mul(x,e.x));
    }

    @Override
    public Group2Element invExp(ZpElement exp) {
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
    public PabcSerializer.Group2Element toProto() {
        return PabcSerializer.Group2Element.newBuilder()
                .setX(transformToProto(x))
                .build();
    }

    @Override
    public byte[] toBytes() {
        return ecp2ToBytes(x);
    }

    /**
     * Turns an ECP2 into a byte array
     *
     * @param e The ECP2 to turn into bytes
     * @return A byte array representation of the ECP2
     */
    private static byte[] ecp2ToBytes(ECP2 e) {
        byte[] ret = new byte[4 * PairingBLS461.FIELD_BYTES + 1];
        e.toBytes(ret, false);
        return ret;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group2ElementBLS461 that = (Group2ElementBLS461) o;
        return x.equals(that.x);
    }

    /**
     * Returns an amcl.BN256.ECP2 on input of an ECP2 protobuf object.
     *
     * @param w a protobuf object representing an ECP2
     * @return a ECP2 created from the protobuf object
     */
    private static ECP2 transformFromProto(PabcSerializer.ECP2 w) {
        byte[] valuexa = w.getXa().toByteArray();
        byte[] valuexb = w.getXb().toByteArray();
        byte[] valueya = w.getYa().toByteArray();
        byte[] valueyb = w.getYb().toByteArray();
        FP2 valuex = new FP2(BIG.fromBytes(valuexa), BIG.fromBytes(valuexb));
        FP2 valuey = new FP2(BIG.fromBytes(valueya), BIG.fromBytes(valueyb));
        return new ECP2(valuex, valuey);
    }

    /**
     * Converts an amcl.BN256.ECP2 into an ECP2 protobuf object.
     *
     * @param w an ECP2 to be transformed into a protobuf object
     * @return a protobuf representation of the ECP2
     */
    private static PabcSerializer.ECP2 transformToProto(ECP2 w) {

        byte[] valueXA = new byte[PairingBLS461.FIELD_BYTES];
        byte[] valueXB = new byte[PairingBLS461.FIELD_BYTES];
        byte[] valueYA = new byte[PairingBLS461.FIELD_BYTES];
        byte[] valueYB = new byte[PairingBLS461.FIELD_BYTES];

        w.getX().getA().toBytes(valueXA);
        w.getX().getB().toBytes(valueXB);
        w.getY().getA().toBytes(valueYA);
        w.getY().getB().toBytes(valueYB);

        return PabcSerializer.ECP2.newBuilder()
                .setXa(ByteString.copyFrom(valueXA))
                .setXb(ByteString.copyFrom(valueXB))
                .setYa(ByteString.copyFrom(valueYA))
                .setYb(ByteString.copyFrom(valueYB))
                .build();
    }

}
