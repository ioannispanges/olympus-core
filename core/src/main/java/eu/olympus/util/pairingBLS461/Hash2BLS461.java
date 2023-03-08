package eu.olympus.util.pairingBLS461;

import eu.olympus.util.pairingInterfaces.Group2Element;
import eu.olympus.util.pairingInterfaces.Group3Element;
import eu.olympus.util.pairingInterfaces.Hash2;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSverfKey;
import org.apache.commons.codec.Charsets;
import org.miracl.core.BLS12461.FP12;

import java.util.SortedSet;
import java.util.TreeSet;

import static eu.olympus.util.Util.append;

public class Hash2BLS461 implements Hash2 {

    private PairingBuilderBLS461 builder=new PairingBuilderBLS461();

    @Override
    public ZpElement hash(String m, PSverfKey avk, Group2Element sigma1, Group2Element sigma2, Group3Element prodT) {
        if(!(sigma1 instanceof Group2ElementBLS461))
            throw new IllegalArgumentException("Elements must be BLS461");
        if(!(sigma2 instanceof Group2ElementBLS461))
            throw new IllegalArgumentException("Elements must be BLS461");
        if(!(prodT instanceof Group3ElementBLS461))
            throw new IllegalArgumentException("Elements must be BLS461");
        if(!(avk.getVX() instanceof Group1ElementBLS461))
            throw new IllegalArgumentException("Elements must be BLS461");

        Group1ElementBLS461 x=(Group1ElementBLS461)avk.getVX();
        Group1ElementBLS461 y_m=(Group1ElementBLS461)avk.getVY_m();
        Group1ElementBLS461 y_epoch=(Group1ElementBLS461)avk.getVY_epoch();
        byte[] b= x.toBytes();
        b=append(b,m.getBytes(Charsets.UTF_8));
        b=append(b,y_m.toBytes());
        b=append(b,y_epoch.toBytes());
        SortedSet<String> keys = new TreeSet<>(avk.getVY().keySet());
        for(String yi:keys){
            b=append(b,avk.getVY().get(yi).toBytes());
        }
        b=append(b,sigma1.toBytes());
        b=append(b,sigma2.toBytes());
        b=append(b,fp12ToBytes(((Group3ElementBLS461) prodT).x));
        return builder.hashZpElementFromBytes(b);
    }



    /**
     * Turns an FP12 into a byte array
     * @param e The FP12 to turn into bytes
     * @return A byte array representation of the FP12
     */
    private static byte[] fp12ToBytes(FP12 e) {
        byte[] ret = new byte[12 * PairingBLS461.FIELD_BYTES];
        e.toBytes(ret);
        return ret;
    }

}
