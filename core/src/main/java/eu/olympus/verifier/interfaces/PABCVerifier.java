package eu.olympus.verifier.interfaces;

import eu.olympus.model.Policy;
import eu.olympus.verifier.VerificationResult;


public interface PABCVerifier {



    /**
     * Verify if a PABC (PS) presentation token is valid, was generated using a credential that is still valid and conforms to a specific policy.
     * @param token Presentation token.
     * @param policy Policy it needs to comply to, including message signed.
     * @return VerificationResult.VALID if the token is valid and fulfills all the policy. A description of the error otherwise.
     */
    VerificationResult verifyPresentationToken(String token, Policy policy);
}
