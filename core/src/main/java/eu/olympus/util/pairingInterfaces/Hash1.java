package eu.olympus.util.pairingInterfaces;


import eu.olympus.util.psmultisign.PSverfKey;

/**
 * Interface for the hash function H1: G^2N -> X < G^N needed for the PS scheme.
 */
public interface Hash1 {

    /**
     * Obtain the result of the hash function.
     * @param vks An array of verification keys.
     * @return A Zp element for each verification key.
     */
    ZpElement[] hash(PSverfKey[] vks);
}
