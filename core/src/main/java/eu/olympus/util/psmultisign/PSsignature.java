package eu.olympus.util.psmultisign;

import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.util.multisign.MSsignature;
import eu.olympus.util.pairingBLS461.Group2ElementBLS461;
import eu.olympus.util.pairingBLS461.ZpElementBLS461;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.ZpElement;

/**
 * Signature obtained using a PS signing scheme.
 */
public class PSsignature implements MSsignature {

    private ZpElement mPrim;
    private Group2Element sigma1;
    private Group2Element sigma2;

    public PSsignature(ZpElement mPrim, Group2Element sigma1, Group2Element sigma2) {
        this.mPrim = mPrim;
        this.sigma1 = sigma1;
        this.sigma2 = sigma2;
    }

    public  PSsignature(PabcSerializer.PSsignature signature){
        this.mPrim=new ZpElementBLS461(signature.getMPrim());
        this.sigma1=new Group2ElementBLS461(signature.getSigma1());
        this.sigma2=new Group2ElementBLS461(signature.getSigma2());
    }

    public ZpElement getMPrim() {
        return mPrim;
    }

    public Group2Element getSigma1() {
        return sigma1;
    }

    public Group2Element getSigma2() {
        return sigma2;
    }

    public PabcSerializer.PSsignature toProto() {
        return PabcSerializer.PSsignature.newBuilder()
                .setMPrim(mPrim.toProto())
                .setSigma1(sigma1.toProto())
                .setSigma2(sigma2.toProto())
                .build();
    }
}
