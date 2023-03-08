package eu.olympus.util.multisign;

/**
 * Public parameters needed for the signature scheme. Right now it is assumed that at least the public parameters include
 * at least those necessary for the setup process of the scheme, so another party can create an equivalent instance of it.
 */
public interface MSpublicParam {

    /**
     * Obtain one of the arguments needed for MS setup.
     * @return Number of parties that will participate in the signing process creating a signature share.
     */
    int getN();

    /**
     * Obtain one of the arguments needed for MS setup.
     * @return Auxiliary arguments for the setup process.
     */
    MSauxArg getAuxArg();

    /**
     * Return a base 64 encoding of the parameters
     * @return a base 64 encoding of the parameters
     */
    String getEncoded();
}
