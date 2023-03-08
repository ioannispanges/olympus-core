package eu.olympus.util.psmultisign;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSzkToken;
import eu.olympus.util.pairingBLS461.Group2ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.HashMap;
import java.util.Map;

/**
 * Presentation token for ZK proofs in a PS-MS signature scheme.
 */
public class PSzkToken implements MSzkToken {

    private Group2Element sigma1;
    private Group2Element sigma2;
    private ZpElement c;
    private Map<String, ZpElement> vaj;
    private ZpElement vt;
    private ZpElement vaPrim;

    public PSzkToken(Group2Element sigma1, Group2Element sigma2, ZpElement c, Map<String, ZpElement> vaj, ZpElement vt, ZpElement vaPrim) {
        this.sigma1 = sigma1;
        this.sigma2 = sigma2;
        this.c = c;
        this.vaj = vaj;
        this.vt = vt;
        this.vaPrim = vaPrim;
    }

    public PSzkToken(PabcSerializer.PSzkToken zkToken) {
        this.sigma1=new Group2ElementBLS461(zkToken.getSigma1());
        this.sigma2=new Group2ElementBLS461(zkToken.getSigma2());
        this.c=new ZpElementBLS461(zkToken.getC());
        this.vaj=new HashMap<>();
        Map<String,PabcSerializer.ZpElement> protoAttr=zkToken.getRevealedAttributesMap();
        for(String attrName:protoAttr.keySet()){
            vaj.put(attrName,new ZpElementBLS461(protoAttr.get(attrName)));
        }
        this.vt=new ZpElementBLS461(zkToken.getVt());
        this.vaPrim=new ZpElementBLS461(zkToken.getVaPrim());
    }

    public Group2Element getSigma1() {
        return sigma1;
    }

    public Group2Element getSigma2() {
        return sigma2;
    }

    public ZpElement getC() {
        return c;
    }

    public Map<String, ZpElement> getVaj() {
        return vaj;
    }

    public ZpElement getVt() {
        return vt;
    }

    public ZpElement getVaPrim() {
        return vaPrim;
    }

    public PabcSerializer.PSzkToken toProto(){
        Map<String,PabcSerializer.ZpElement> protoAttr=new HashMap<>();
        for(String attrName:vaj.keySet()){
            protoAttr.put(attrName,vaj.get(attrName).toProto());
        }
        return PabcSerializer.PSzkToken.newBuilder()
                .setSigma1(sigma1.toProto())
                .setSigma2(sigma2.toProto())
                .setC(c.toProto())
                .putAllRevealedAttributes(protoAttr)
                .setVt(vt.toProto())
                .setVaPrim(vaPrim.toProto())
                .build();
    }
}
