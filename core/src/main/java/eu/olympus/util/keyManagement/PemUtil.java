package eu.olympus.util.keyManagement;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;

public class PemUtil {
  public static final int CHARS_IN_LINE = 64;

  /**
   * Base64 encode bytes and prepends and postpends
   * ------- BEGIN type ------
   * ------- END type -------
   */
  public static String encodeDerToPem(byte[] derData, String type) throws IOException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    os.write(printDER(derData, type).getBytes(StandardCharsets.US_ASCII));
    os.close();
    return os.toString();
  }

  public static String printDER(byte[] input, String type) {
    byte[] encodedCert = Base64.encodeBase64(input);
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN " + type + "-----\n");
    addBytes(builder, encodedCert);
    builder.append("-----END " + type + "-----");
    return builder.toString();
  }

  private static void addBytes(StringBuilder builder, byte[] encoding){
    int start = 0;
    while (start < encoding.length) {
      int end = encoding.length - (start + CHARS_IN_LINE) > 0 ?
          start + CHARS_IN_LINE : encoding.length;
      builder.append(new String(Arrays.copyOfRange(encoding, start, end)));
      builder.append('\n');
      start += CHARS_IN_LINE;
    }
  }
}
