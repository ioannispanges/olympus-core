package eu.olympus.util.psmultisign;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.pairingBLS461.Group1ElementBLS461;
import eu.olympus.util.pairingInterfaces.Group1Element;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Verification key for a PS signing scheme.
 */
public class PSverfKey implements MSverfKey {

    private Group1Element vx;
    private Group1Element vy_m;
    private Group1Element vy_epoch;
    private Map<String, Group1Element> vy;

    public PSverfKey(Group1Element vx, Group1Element vy_m, Map<String, Group1Element> vy, Group1Element vy_epoch) {
        this.vx = vx;
        this.vy_m = vy_m;
        this.vy = vy;
        this.vy_epoch=vy_epoch;
    }

    public PSverfKey(byte[] verfKey) throws InvalidProtocolBufferException {
        PabcSerializer.PSverfKey protoKey=PabcSerializer.PSverfKey.parseFrom(verfKey);
        this.vx=new Group1ElementBLS461(protoKey.getVx());
        this.vy_m=new Group1ElementBLS461(protoKey.getVyM());
        this.vy_epoch=new Group1ElementBLS461(protoKey.getVyEpoch());
        this.vy=new HashMap<>();
        Map<String,PabcSerializer.Group1Element> protoMap=protoKey.getVyMap();
        for(String attr:protoMap.keySet())
            this.vy.put(attr,new Group1ElementBLS461(protoMap.get(attr)));
    }

    public Group1Element getVX() {
        return vx;
    }

    public Group1Element getVY_m() {
        return vy_m;
    }

    public Group1Element getVY_epoch() {
        return vy_epoch;
    }

    public Map<String, Group1Element> getVY() {
        return vy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PSverfKey pSverfKey = (PSverfKey) o;
        return Objects.equals(vx, pSverfKey.vx) &&
                Objects.equals(vy_m, pSverfKey.vy_m) &&
                Objects.equals(vy, pSverfKey.vy);
    }

    @Override
    public String getAlgorithm() {
        return "PS";
    }

    @Override
    public String getFormat() {
        return "Proto";
    }

    @Override
    public byte[] getEncoded() {
        return toProto().toByteArray();
    }


    private PabcSerializer.PSverfKey toProto() {
        Map<String,PabcSerializer.Group1Element> proto=new HashMap<>();
        for(String attr:vy.keySet()){
            proto.put(attr,vy.get(attr).toProto());
        }
        return PabcSerializer.PSverfKey.newBuilder()
                .setVx(vx.toProto())
                .setVyM(vy_m.toProto())
                .setVyEpoch(vy_epoch.toProto())
                .putAllVy(proto)
                .build();
    }
}
