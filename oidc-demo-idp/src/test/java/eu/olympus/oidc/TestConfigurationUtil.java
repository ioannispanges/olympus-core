package eu.olympus.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionDate;
import eu.olympus.model.AttributeDefinitionInteger;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.DateGranularity;
import eu.olympus.util.ConfigurationUtil;
import eu.olympus.util.keyManagement.SecureStoreUtil;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;

public class TestConfigurationUtil extends ConfigurationUtil{

//	@Ignore
	@Test
	public void generateOIDCDockerConfiguration() throws Exception{
		rng = new SecureRandom();
		//Server and TLS related configuration:
		servers = new String[] {"https://host.docker.internal:9933", "https://host.docker.internal:9934", "https://host.docker.internal:9935"};
		portNumbers = new int[] {9080, 9081, 9082};
		tlsPortNumbers = new int[] {9933, 9934, 9935};
		
		TLS_KEYSIZE = 2048;
		TLS_RDN = new String[] {"CN=127.0.0.1, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown", "CN=127.0.0.1, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown", "CN=127.0.0.1, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown"};
		SAN = new String[][] {{"localhost", "host.docker.internal","idp1", "idp1.olympus.projects.alexandra.dk"},{"localhost", "idp2","host.docker.internal", "idp2.olympus.projects.alexandra.dk"},{"localhost","idp3", "host.docker.internal", "idp3.olympus.projects.alexandra.dk"}};
		
		keyStorePaths = new String[] {"/app/config/server-1.jks", "/app/config/server-2.jks", "/app/config/server-3.jks"};
		keyStorePasswords = new String[] {"server1", "server2", "server3"};
		keyNames = new String[] {"private-key", "private-key", "private-key"};
		
		trustStorePaths = new String[] {"/app/config/truststore.jks", "/app/config/truststore.jks", "/app/config/truststore.jks"}; 
		trustStorePassword = "OLYMPUS"; 
		certNames = new String[] {"oidc-localhost", "oidc-localhost", "oidc-localhost"};

		
		//IdP related configuration
		issuerId = "https://olympus-vidp.com/issuer1";
		RDN = "CN=olympus-vidp.com,O=Olympus,OU=www.olympus-project.eu,C=EU";
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048, new SecureRandom());
		sk = (RSAPrivateCrtKey)generator.generateKeyPair().getPrivate();
		attrDefinitions = generateAttributeDefinitions();
		waitTime = 1000;
		allowedTimeDifference = 10000;
		lifetime = 72000000l;
		sessionLength = 60000l;
		
		generateConfigurations();

		// Write output to files
		outputPath = TestParameters.TEST_DIR + "volatile";
		Files.createDirectories(Paths.get(outputPath));
		ObjectMapper mapper = new ObjectMapper();
		for(int i = 0; i< servers.length; i++) {
			File f = new File(outputPath+"/auto-server-"+i+".json");
			mapper.writeValue(f, configurations[i]);
			SecureStoreUtil.writeSecurityStore(keystores[i], keyStorePasswords[i], outputPath+"/server-"+i+".jks");
		}
		SecureStoreUtil.writeSecurityStore(trustStore, trustStorePassword, outputPath+"/truststore.jks");
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
