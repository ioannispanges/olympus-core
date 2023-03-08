package eu.olympus.unit.server;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeType;
import org.junit.Test;

import eu.olympus.server.JWTTokenGenerator;
import eu.olympus.server.interfaces.TokenGenerator;
import eu.olympus.verifier.JWTVerifier;

public class TestJWTTokenGenerator {
	
	@Test
	public void testGenerateKey() throws Exception {
		JWTTokenGenerator generator = new JWTTokenGenerator();
		
		generator.setKeys(TestParameters.getRSAPrivateKey1(), TestParameters.getRSAPublicKey1());
		PublicKey pk = generator.getPublicKey();
		assertThat(pk, is(instanceOf(RSAPublicKey.class)));
	}
	
	@Test
	public void testGenerateTokenAndVerify() throws Exception{
		JWTTokenGenerator generator = new JWTTokenGenerator();
		generator.setKeys(TestParameters.getRSAPrivateKey1(), TestParameters.getRSAPublicKey1());
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John doe"));
		String token = generator.generateToken(attributes);
		JWTVerifier verifier = new JWTVerifier(generator.getPublicKey());
		assertThat(verifier.verify(token), is(true));
	}
	
	@Test(expected=Exception.class)
	public void testGenerateTokenNoKeyGenerator() throws Exception {
		TokenGenerator generator = new JWTTokenGenerator();
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("name", new Attribute("John doe"));
		generator.generateToken(attributes);
		fail();
	}

	
	@Test
	public void testGenerateTokenAndVerifyInteger() throws Exception{
		JWTTokenGenerator generator = new JWTTokenGenerator();
		
		generator.setKeys(TestParameters.getRSAPrivateKey1(), TestParameters.getRSAPublicKey1());
		Map<String, Attribute> attributes = new HashMap<>();
		attributes.put("age", new Attribute(10));
		
		String token = generator.generateToken(attributes);
		JWTVerifier verifier = new JWTVerifier(generator.getPublicKey());
		assertThat(verifier.verify(token), is(true));
	}
	
	@Test(expected=Exception.class)
	public void testGenerateTokenAndVerifyInvalid() throws Exception{
		JWTTokenGenerator generator = new JWTTokenGenerator();
		
		generator.setKeys(TestParameters.getRSAPrivateKey1(), TestParameters.getRSAPublicKey1());
		Map<String, Attribute> attributes = new HashMap<>();
		List<String> restrictions = new LinkedList<String>();
		restrictions.add("vegan");
		restrictions.add("gluten");
		restrictions.add("vegetarian");
		attributes.put("diet", new Attribute(restrictions, AttributeType.STRING));
		
		generator.generateToken(attributes);
		fail();
	}
	
}
