package eu.olympus.unit.util;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.junit.Test;

import eu.olympus.model.Attribute;
import eu.olympus.util.Util;
import org.miracl.core.BLS12461.BIG;
import org.miracl.core.BLS12461.ROM;

public class TestUtil{
	private static final String bls12461Order = "521481194400158902870293791036394582812650143983424074083311820261824039635303638490268303361";

	@Test
	public void testConvertToBigInteger() {
		BigInteger bigInt = Util.BIGToBigInteger(new BIG(ROM.CURVE_Order));
		assertThat(bigInt.toString(), is(bls12461Order));
	}

	@Test
	public void testConvertToBIG() {
		BigInteger bigInt = new BigInteger(bls12461Order);
		BIG res = Util.BigIntegerToBIG(bigInt);
		assertThat(BIG.comp(res, new BIG(ROM.CURVE_Order)), is(0));
	}

	@Test
	public void testConvertToBIG2() {
		BigInteger bigInt = Util.BIGToBigInteger(new BIG(ROM.Modulus)).subtract(BigInteger.ONE);
		BIG res = Util.BigIntegerToBIG(bigInt);
		assertThat(BIG.comp(res, new BIG(ROM.Modulus).minus(new BIG(1))), is(0));
	}

	@Test
	public void testConvertToBIG3() {
		BigInteger bigInt = Util.BIGToBigInteger(new BIG(ROM.Modulus)).add(BigInteger.ONE);
		BIG res = Util.BigIntegerToBIG(bigInt);
		assertThat(BIG.comp(res, new BIG(1)), is(0));
	}

	@Test
	public void testConvertToBIG4() {
		BigInteger bigInt = new BigInteger("42");
		BIG res = Util.BigIntegerToBIG(bigInt);
		assertThat(BIG.comp(res, new BIG(42)), is(0));
	}

	@Test
	public void testIdenticalMaps() {

		Map<String, Attribute> map1 = new HashMap<>();
		Map<String, Attribute> map2 = new HashMap<>();
		Map<String, Attribute> map3 = new HashMap<>();
		List<Map<String, Attribute>> maps = new LinkedList<>();
		maps.add(map1);
		maps.add(map2);
		maps.add(map3);
		
		assertTrue(Util.verifyIdenticalMaps(maps));
		
		map1.put("name", new Attribute("Joe"));
		assertFalse(Util.verifyIdenticalMaps(maps));
		map2.put("name", new Attribute("Joe"));
		map3.put("name", new Attribute("Joe"));
		assertTrue(Util.verifyIdenticalMaps(maps));
		
		map1.put("age", new Attribute(5));
		map2.put("age", new Attribute(5));
		map3.put("age", new Attribute(7));
		assertFalse(Util.verifyIdenticalMaps(maps));
	}

	@Test (expected = IllegalArgumentException.class)
	public void testUnevenLengthXor() {
		byte[] input1 = new byte[] { (byte) 0x01, (byte) 0x02 };
		byte[] input2 = new byte[] { (byte) 0x01, (byte) 0x02, (byte) 0x03};
		Util.xorArray(input1, input2);
	}
	
	@Test
	public void testIdenticalStrings() {
		List<String> strings = new LinkedList<>();
		strings.add("aab");
		strings.add("aab");
		strings.add("aab");
		assertTrue(Util.verifyIdenticalStrings(strings));
		
		strings.add("aaaa");
		assertFalse(Util.verifyIdenticalStrings(strings));
		
		strings.remove("aaaa");
		assertTrue(Util.verifyIdenticalStrings(strings));
		
		strings.add(0, "bbb");
		assertFalse(Util.verifyIdenticalStrings(strings));
	}

	
}
