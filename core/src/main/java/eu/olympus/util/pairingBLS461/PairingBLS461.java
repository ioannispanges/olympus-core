package eu.olympus.util.pairingBLS461;

import eu.olympus.util.Pair;
import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Group1Element;
import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.Pairing;
import org.miracl.core.BLS12461.*;

import java.util.Collection;

public class PairingBLS461 implements Pairing {

    public static final BIG p=new BIG(ROM.CURVE_Order);
    static final int FIELD_BYTES= CONFIG_BIG.MODBYTES;


    @Override
    public Group3ElementBLS461 pair(Group2Element el1, Group1Element el2) {
        if(!(el1 instanceof Group2ElementBLS461))
            throw new IllegalArgumentException("el1 must be Group2ElementBLS461");
        if(!(el2 instanceof Group1ElementBLS461))
            throw new IllegalArgumentException("el2 must be Group1ElementBLS461");
        ECP2 e2= ((Group2ElementBLS461) el1).x;
        ECP e1= ((Group1ElementBLS461) el2).x;
        return new Group3ElementBLS461(PAIR.fexp(PAIR.ate(e2,e1)));
    }

    @Override
    public Group3Element multiPair(Collection<Pair<Group2Element,Group1Element>> elements) {
        FP12[] r=PAIR.initmp();
        for(Pair<Group2Element,Group1Element> el:elements){
            if(!(el.getFirst() instanceof Group2ElementBLS461))
                throw new IllegalArgumentException("el1 must be Group2ElementBLS461");
            if(!(el.getSecond()   instanceof Group1ElementBLS461))
                throw new IllegalArgumentException("el2 must be Group1ElementBLS461");
            ECP2 e2= ((Group2ElementBLS461) el.getFirst()).x;
            ECP e1= ((Group1ElementBLS461) el.getSecond()).x;
            PAIR.another(r,e2,e1);
        }
        FP12 f=PAIR.miller(r);
        return new Group3ElementBLS461(PAIR.fexp(f));
    }

}
