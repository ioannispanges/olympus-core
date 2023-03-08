package eu.olympus.server.interfaces;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * The external interface for the IdP. This should be implemented
 * as a REST interface by all partial IdPs.
 */
public interface VirtualIdP {
	/**
	 * Return the ID used to identify this IdP
	 */
	public int getId();

	public Certificate getCertificate() throws CertificateException;

}
