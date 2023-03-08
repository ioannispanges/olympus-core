package eu.olympus.util.pairingBLS461;

import eu.olympus.util.pairingInterfaces.Hash1;
import eu.olympus.util.pairingInterfaces.ZpElement;
import eu.olympus.util.psmultisign.PSverfKey;

import java.util.SortedSet;
import java.util.TreeSet;

import static eu.olympus.util.Util.append;

public class Hash1BLS461 implements Hash1 {

    private PairingBuilderBLS461 builder=new PairingBuilderBLS461();


    @Override
    public ZpElement[] hash(PSverfKey[] vks) {
        ZpElement[] t= new ZpElement[vks.length];
        for(int i=0;i<vks.length;i++)
            t[i]=hashVK(vks[i]);
        return t;
    }

    private ZpElement hashVK(PSverfKey vk) {
        if(!(vk.getVX() instanceof Group1ElementBLS461))
            throw new IllegalArgumentException("Elements must be BLS461");
        Group1ElementBLS461 x=(Group1ElementBLS461)vk.getVX();
        Group1ElementBLS461 y_m=(Group1ElementBLS461)vk.getVY_m();
        Group1ElementBLS461 y_epoch=(Group1ElementBLS461)vk.getVY_epoch();
        byte[] b= x.toBytes();
        b=append(b,y_m.toBytes());
        b=append(b,y_epoch.toBytes());
        SortedSet<String> keys = new TreeSet<>(vk.getVY().keySet());
        for(String yi:keys){
            b=append(b,vk.getVY().get(yi).toBytes());
        }
        return builder.hashZpElementFromBytes(b);
    }


}
