package eu.olympus.cfp.server.identityprovers;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.cfp.model.CreditFile;
import eu.olympus.model.Attribute;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.interfaces.IdentityProver;
import eu.olympus.server.interfaces.Storage;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.HashMap;
import java.util.Map;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

public class CreditFileIdentityProver implements IdentityProver {

	private DocumentBuilderFactory documentBuilderFactory;
	private Key validatingKey;
	private KeyStore trustAnchors;
	private CertStore store;
	private Storage storage;

	/**
	 * TODO: handle certficate/keystores nicer
	 * @param pathToCertificate
	 * @throws Exception
	 */
	public CreditFileIdentityProver(String pathToCertificate, Storage storage) throws Exception {
		this.storage = storage;
		documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        
        FileInputStream fis = new FileInputStream(pathToCertificate);
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        java.security.cert.Certificate cert = null;
        while (bis.available() > 0) {
            cert = cf.generateCertificate(bis);
        }
        validatingKey = cert.getPublicKey();  

        CertStoreParameters params = new CollectionCertStoreParameters();
        store = CertStore.getInstance("Collection", params);
        

        trustAnchors = KeyStore.getInstance("JKS");
        trustAnchors.load(null, null);
        trustAnchors.setCertificateEntry("CFP", cert);
	}
	
	@Override
	public boolean isValid(String input, String username) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			CreditFile proof = mapper.readValue(input, CreditFile.class);
			
			InputSource is = new InputSource(new StringReader((String) proof.getData()));
	        Document doc =
	            documentBuilderFactory.newDocumentBuilder().parse(is);


	        // Find Signature element
	        NodeList nl =
	            doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
	        if (nl.getLength() == 0) {
	            throw new SAXException("Cannot find Signature element");
	        }

        // Create a DOM XMLSignatureFactory that will be used to unmarshal the
        // document containing the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        
        
        // Create a DOMValidateContext and specify a KeyValue KeySelector
        // and document context
        DOMValidateContext valContext = new DOMValidateContext(validatingKey, nl.item(0));
        
        valContext.setDefaultNamespacePrefix("");
        // unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        
        CertificateValidationProvider certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, store);
        XadesVerificationProfile p = new XadesVerificationProfile(certValidator);
        XadesVerifier v = p.newVerifier();
        
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions();
        
        Element elm = (Element)nl.item(0);
        try{
        	v.verify(elm, options);
        } catch(Exception e) {
        	System.out.println("XAdESVerification failed!");
        	return false;
        }
        
        
        // Validate the XMLSignature (generated above)
        boolean coreValidity = false;
        try {
        	coreValidity = signature.validate(valContext);
        } catch(Exception e) {
        	e.printStackTrace();
        	return false;
        }

        // Check core validation status
        if (coreValidity == false) {
            System.err.println("Signature failed core validation");
         //   boolean sv = signature.getSignatureValue().validate(valContext);
          //  System.out.println("signature validation status: " + sv);
            // check the validation status of each Reference
          //  Iterator i = signature.getSignedInfo().getReferences().iterator();
          //  for (int j=0; i.hasNext(); j++) {
          //      boolean refValid =
          //          ((Reference) i.next()).validate(valContext);
          //      System.out.println("ref["+j+"] validity status: " + refValid);
          //  }
    		return false;
        } else {
            System.out.println("Signature passed core validation");
            return true;
        }
		} catch(SAXException | IOException 
				| ParserConfigurationException | MarshalException 
				| NoSuchAlgorithmException | NoSuchProviderException
				| XadesProfileResolutionException e) {
			System.out.println("XML parsing error");
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public void addAttributes(String input, String username) {

		try {
			ObjectMapper mapper = new ObjectMapper();
			CreditFile proof = mapper.readValue(input, CreditFile.class);
			InputSource is = new InputSource(new StringReader((String) proof.getData()));
			Document doc = documentBuilderFactory.newDocumentBuilder().parse(is);
			NodeList nl =
					doc.getElementsByTagNameNS("", "BLOQUEIDENTIFICATIVO");
			if (nl.getLength() == 0) {
				throw new SAXException("Cannot find  element");
			}
			Map<String, Attribute> identityAttributes = parseIdentificationData(nl.item(0).getChildNodes());

			nl = doc.getElementsByTagNameNS("", "BLOQUEINFORMATIVO");
			if (nl.getLength() == 0) {
				throw new SAXException("Cannot find  element");
			}
			Map<String, Attribute> informationAttributes = parseInformationData(nl.item(0).getChildNodes());

			//TODO do some proper adding
			storage.addAttributes(username, identityAttributes);
			storage.addAttributes(username, informationAttributes);

		} catch (SAXException | IOException | ParserConfigurationException | OperationFailedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private Map<String, Attribute> parseIdentificationData(NodeList nl) {
		HashMap<String, Attribute> map = new HashMap<String, Attribute>();

		for(int i = 0; i< nl.getLength(); i++) {
			if(nl.item(i).getAttributes() != null) {
				map.put(nl.item(i).getAttributes().getNamedItem("label").getNodeValue(), new Attribute(nl.item(i).getTextContent()));
			}
		}
		return map;
	}

	private Map<String, Attribute> parseInformationData(NodeList nl) {
		HashMap<String, Attribute> map = new HashMap<String, Attribute>();
		//System.out.println("--"+nl.item(1).getNodeName());
		nl = nl.item(1).getChildNodes();
        for(int i = 0; i< nl.getLength(); i++) {
        	//System.out.println(nl.item(i).getNodeName());
        	
        	if(nl.item(i).getAttributes() != null) {
        		if(nl.item(i).getChildNodes().getLength() == 1) {
            		//System.out.println(nl.item(i).getAttributes().getNamedItem("label").getNodeValue() + " : "+nl.item(i).getTextContent());
            		map.put(nl.item(i).getAttributes().getNamedItem("label").getNodeValue(), new Attribute(nl.item(i).getTextContent()));
        		} else {
        			NodeList children = nl.item(i).getChildNodes();
        	
        			Map<String, Attribute> subMap = new HashMap<String, Attribute>();
        			for(int j = 0; j< children.getLength(); j++) {
        	        	//System.out.println(children.item(j).getNodeName());
        	        	
        	        	if(children.item(j).getAttributes() != null) {
        	        		if(children.item(j).getChildNodes().getLength() == 1) {
        	            	//	System.out.println(children.item(j).getAttributes().getNamedItem("label").getNodeValue() + " : "+children.item(j).getTextContent());
        	            		subMap.put(children.item(j).getAttributes().getNamedItem("label").getNodeValue(), new Attribute(children.item(j).getTextContent()));
        	        		} else {
        	        			//System.out.println("this is bad");
        	        		}
        	        	}
        	        }
        			
        			//TODO Handle attributes
        			//map.put(nl.item(i).getAttributes().getNamedItem("label").getNodeValue(), subMap);
        			map.putAll(subMap);
        		}
        	}
        }
		return map;
	}
	
}
