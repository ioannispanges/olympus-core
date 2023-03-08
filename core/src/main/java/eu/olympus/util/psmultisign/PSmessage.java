package eu.olympus.util.psmultisign;

import eu.olympus.util.multisign.MSmessage;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.Map;

/**
 * Messages that can be signed using a PS signature scheme. For signing, a map of named attributes represented by Zp elements and
 * an epoch (again, a Zp element) are required.
 */
public class PSmessage implements MSmessage {
    private Map<String, ZpElement> m;
    private ZpElement epoch;

    public PSmessage(Map<String, ZpElement> m, ZpElement epoch) {
        this.m = m;
        this.epoch=epoch;
    }

    public Map<String, ZpElement> getM() {
        return m;
    }

    public ZpElement getEpoch(){
        return epoch;
    }
}