package eu.olympus.util.pairingInterfaces;

import eu.olympus.util.Pair;

import java.util.List;

/**
 * Interface for the hash function H0:Z^k -> Zp x G needed for the PS scheme.
 */
public interface Hash0 {

    /**
     * Obtain the result of the hash function.
     * @param m An array of Zp elements.
     * @return A Zp element and a Group2 element.
     */
    Pair<ZpElement,Group2Element> hash(List<ZpElement> m);
}
