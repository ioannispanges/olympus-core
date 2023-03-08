package eu.olympus.verifier;

public enum VerificationResult {

	VALID,
	INVALID_SIGNATURE,
	BAD_TIMESTAMP,
	POLICY_NOT_FULFILLED,
	INVALID_POLICY
}
