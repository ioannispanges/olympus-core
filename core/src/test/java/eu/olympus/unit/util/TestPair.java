package eu.olympus.unit.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import org.junit.Test;

import eu.olympus.model.Attribute;
import eu.olympus.util.Pair;

public class TestPair{

	@Test
	public void testBasics() {
		Pair<String, Attribute> pair1 = new Pair<>("key", new Attribute("Joe"));
		Pair<String, Attribute> pair2 = new Pair<>("key", new Attribute("Joe"));
		Pair<String, Attribute> pair3 = new Pair<>("value", new Attribute("Joe"));
		Pair<String, Attribute> pair4 = new Pair<>("key", new Attribute("Bob"));
		Pair<String, String> pair5 = new Pair<>("key", "Joe");
		Pair<Integer, Attribute> pair6 = new Pair<>(6, new Attribute("Joe"));
		
		assertEquals(pair1, pair1);
		assertEquals("key", pair1.getFirst());
		assertEquals(new Attribute("Joe"), pair1.getSecond());
		assertEquals(pair1, pair2);
		assertNotEquals(pair1, null);
		assertNotEquals(pair1, "Joe");
		assertNotEquals(pair1, pair3);
		assertNotEquals(pair1, pair4);
		assertNotEquals(pair1, pair5);
		assertNotEquals(pair1, pair6);
	}
	
	
	
}
