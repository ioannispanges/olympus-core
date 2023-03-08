package eu.olympus.util;

import eu.olympus.model.Attribute;
import org.miracl.core.BLS12461.BIG;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.miracl.core.BLS12461.ROM;
import java.util.TimeZone;

public class Util {

	// Magic number that depends on the underlying curve used
	public static final int BYTES_IN_BIG = 58;
	public static final String formatRFC3339UTC = "yyyy-MM-dd'T'HH:mm:ss";


	private Util() {}
	
	public static boolean verifyIdenticalMaps(List<Map<String, Attribute>> maps) {
		Map<String, Attribute> firstMap = maps.get(0);
		for(Map<String, Attribute> current: maps) {
			if(!firstMap.equals(current)) {
				return false;
			}
		}
		return true;
	}
	
	public static boolean verifyIdenticalStrings(List<String> strings) {
		String first = strings.get(0);
		for(String current: strings) {
			if(!first.equals(current)) {
				return false;
			}
		}
		return true;
	}

	public static BigInteger BIGToBigInteger(BIG big) {
		String bigString = big.toString(); // Hex string
		char[] array = bigString.toCharArray();
		BigInteger res = BigInteger.ZERO;
		int power = 0;
		final BigInteger sixteen = BigInteger.valueOf(16);
		for (int i = array.length-1; i >= 0; i--) {
			// String is the HEX representation so we must convert the character to int
			int intVal = Character.digit(array[i], 16);
			BigInteger currentVal = BigInteger.valueOf(intVal).multiply(sixteen.pow(power));
			res = res.add(currentVal);
			power++;
		}
		return res;
	}

	public static BIG BigIntegerToBIG(BigInteger input) {
		// The maxValue we can have in a BIG is the modulus of the underlying field of the curve we use
		BigInteger maxValue = BIGToBigInteger(new BIG(ROM.Modulus));
		BigInteger reducedInput = input.mod(maxValue);
		byte[] resArray = new byte[BYTES_IN_BIG];
		byte[] tempArray = reducedInput.toByteArray();
		int j = 0;
		// Reverse order since BIG is stored in little endian and BigInteger is stored in big endian
		for (int i = resArray.length-tempArray.length; i < resArray.length; i++) {
			resArray[i] = tempArray[j];
			j++;
		}
		return BIG.fromBytes(resArray);
	}

	public static byte[] xorArray(byte[] first, byte[] second) {
		if (first.length != second.length) {
			throw new IllegalArgumentException("Size of the two arrays to xor is not equal");
		}
		byte[] res = first.clone();
		for (int i = 0; i < first.length; i++) {
			res[i] ^= second[i];
		}
		return res;
	}


	public static SimpleDateFormat getDateFormatRFC3339UTC() {
		SimpleDateFormat dateFormatRFC3339UTC = new SimpleDateFormat(formatRFC3339UTC);
		dateFormatRFC3339UTC.setTimeZone(TimeZone.getTimeZone("UTC"));
		return dateFormatRFC3339UTC;
	}

	public static String toRFC3339UTC(Date date) {
		return getDateFormatRFC3339UTC().format(date);
	}

	public static Date fromRFC3339UTC(String str) {
		try {
			return getDateFormatRFC3339UTC().parse(str);
		}
		catch (ParseException e) { //TODO Warning/throw exception/default value?
			return null;
		}
	}


	/**
	 * Computes the minimum m so that m=2^n and val<=2^m-1
 	 * @param val A positive BigInteger
	 * @return m=2^n, val<=2^m-1
	 */
	public static int nextPowerOfPowerOfTwo(BigInteger val){
		if(val.signum()!=1)
			throw new IllegalArgumentException("Only supported for positive numbers");
		int n=val.bitLength(); //minimum n so val<2^n (val<=2^n-1)
		int highestOneBit = Integer.highestOneBit(n);
		int m=highestOneBit;
		if (n != m) {
			m=m<<1;
		}							// Up to here, m is the smallest power of two so that m>=n
		return m;
	}

	/**
	 * Appends a byte array to an existing byte array
	 * @param data     The data to which we want to append
	 * @param toAppend The data to be appended
	 * @return A new byte[] of data + toAppend
	 */
	public static byte[] append(byte[] data, byte[] toAppend) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		try {
			stream.write(data);
			stream.write(toAppend);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return stream.toByteArray();
	}

}
