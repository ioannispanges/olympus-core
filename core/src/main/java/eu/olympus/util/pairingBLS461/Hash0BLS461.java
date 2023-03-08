package eu.olympus.util.pairingBLS461;

import eu.olympus.util.Pair;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Hash0;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.List;

import static eu.olympus.util.Util.append;

// We could easily separate Hashes from specific curve implementation now, but I think it can be useful to have them
// as part of the "builder" pack (as they will be used in conjunction) and they offer an extra type check security
public class Hash0BLS461 implements Hash0 {

    private PairingBuilderBLS461 builder=new PairingBuilderBLS461();

    @Override
    public Pair<ZpElement, Group2Element> hash(List<ZpElement> m) {
        byte [] b=new byte[0];
        for(ZpElement mi: m) {
            if(!(mi instanceof ZpElementBLS461))
                throw new IllegalArgumentException("Argument must be collection of ZpElementBLS461");
            b=append(b, mi.toBytes());
        }

        ZpElement mPrim=builder.hashZpElementFromBytes(b);
        Group2Element h=builder.hashGroup2ElementFromBytes(b);
        return new Pair<>(mPrim,h);
    }




}
