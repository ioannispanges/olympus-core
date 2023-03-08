package eu.olympus.util.psmultisign;

import eu.olympus.util.multisign.MSprivateKey;
import eu.olympus.util.pairingInterfaces.ZpElement;

import java.util.Map;

/**
 * Secret key for a PS signing scheme.
 */
public class PSprivateKey implements MSprivateKey {
    private ZpElement x;
    private ZpElement y_m;
    private ZpElement y_epoch;
    private Map<String, ZpElement> y;

    public PSprivateKey(ZpElement x, ZpElement y_m, Map<String, ZpElement> y, ZpElement y_epoch ) {
        this.x = x;
        this.y_m = y_m;
        this.y = y;
        this.y_epoch=y_epoch;
    }

    public ZpElement getX() {
        return x;
    }

    public ZpElement getY_m() {
        return y_m;
    }

    public ZpElement getY_epoch() {
        return y_epoch;
    }

    public Map<String, ZpElement> getY() {
        return y;
    }
}
