package eu.olympus.util.pairingInterfaces;

import eu.olympus.util.Pair;

import java.util.Collection;

/**
 * Pairing to be used in the signature scheme.
 */
public interface Pairing {

    /**
     * Calculate the mapping of elements el1, el2.
     * @param el2 Element from group 2.
     * @param el1 Element from group 1.
     * @return e(el1,el2)
     */
    Group3Element pair(Group2Element el2, Group1Element el1);

    /**
     * Calculate the n-pairing.
     * @param elements Pairs of elements that compose the multi-pairing.
     * @return e(elements[0].second,elements[0].first)···e(elements[n-1].second,elements[n-1].first)
     */
    Group3Element multiPair(Collection<Pair<Group2Element,Group1Element>> elements);


}
