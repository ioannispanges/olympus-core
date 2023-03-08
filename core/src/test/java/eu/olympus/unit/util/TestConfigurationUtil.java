package eu.olympus.unit.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import eu.olympus.TestParameters;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionDate;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.DateGranularity;
import eu.olympus.util.ConfigurationUtil;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import org.junit.Test;

public class TestConfigurationUtil extends ConfigurationUtil{


	@Test
	public void testSimpleGeneration() throws Exception{
		rng = new Random();
		//Server and TLS related configuration:
		servers = new String[] {"https://localhost:9933", "https://localhost:9934"};
		portNumbers = new int[] {9080, 9081};
		tlsPortNumbers = new int[] {9933, 9934};
		
		TLS_KEYSIZE = 2048;
		TLS_RDN = new String[] {"CN=127.0.0.1, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown", "CN=127.0.0.1, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown"};
		SAN = new String[][] {null, null};
		
		keyStorePaths = new String[] {"/app/config/server-1.jks", "/app/config/server-2.jks"};
		keyStorePasswords = new String[] {"server1", "server2"};
		keyNames = new String[] {"private-key", "private-key"};
		
		trustStorePaths = new String[] {"/app/config/truststore.jks", "/app/config/truststore.jks"}; 
		trustStorePassword = "OLYMPUS"; 
		certNames = new String[] {"oidc-localhost", "oidc-localhost"};
		
		//IdP related configuration
		issuerId = "https://olympus-vidp.com/issuer1";
		RDN = "CN=olympus-vidp.com,O=Olympus,OU=www.olympus-project.eu,C=EU";

		sk = (RSAPrivateCrtKey)TestParameters.getRSAPrivateKey2();
		attrDefinitions = generateAttributeDefinitions();
		waitTime = 1000;
		allowedTimeDifference = 10000;
		lifetime = 72000000l;
		sessionLength = 60000l;
		
		generateConfigurations();

		for(int i = 0; i< servers.length; i++) {
			
			assertEquals(60000l, configurations[i].getSessionLength());
			assertEquals(9080+i, configurations[i].getPort());
			assertEquals(9933+i, configurations[i].getTlsPort());
			assertEquals(88, configurations[i].getMyAuthorizationCookie().length());
			assertTrue(keystores[i].containsAlias("oidc-localhost"));
			assertEquals(2, trustStore.size());
		}
	}

	private Set<AttributeDefinition> generateAttributeDefinitions() {
		Set<AttributeDefinition> res=new HashSet<>();
		res.add(new AttributeDefinitionString("Name","Name",0,16));
		res.add(new AttributeDefinitionInteger("Age","Age",0,123));
		res.add(new AttributeDefinitionString("Nationality","Nationality",0,16));
		res.add(new AttributeDefinitionDate("DateOfBirth","Date of Birth","1900-01-01T00:00:00","2020-09-01T00:00:00",DateGranularity.DAYS));
		return res;
	}
}
