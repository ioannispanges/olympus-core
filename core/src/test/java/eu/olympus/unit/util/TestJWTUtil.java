package eu.olympus.unit.util;

import eu.olympus.model.Attribute;
import eu.olympus.model.KeyShares;
import eu.olympus.model.RSASharedKey;
import eu.olympus.server.SoftwareServerCryptoModule;
import eu.olympus.server.ThresholdRSAJWTTokenGenerator;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.util.JWTUtil;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class TestJWTUtil {
  private final BigInteger modulus = new BigInteger("72079034227533868401394355596422244630780621384305565440401478379545862690152"
      + "22047310329822466743451691612246401122726819701615915289174650331999840331369"
      + "80468242504320517637285130919069014689785190060445328862225059238793704694539"
      + "1286489954250859794157275839567891438348125299710022246104766838240870482267"
      + "37564557998618127753124252760076317968507014811152556042244129746057863229888"
      + "72822676733913900532118607857609293946250276760541202005817202397031593042714"
      + "40781634936133336439035382528268685766623414345747399812308643093771223189085"
      + "51023061038766679019751925313115639347193496288790711059846580495711802426419");
  private final BigInteger privateKey = new BigInteger("54355402743384330136162958974"
      + "112030977042584647682220046622852197597015821180"
      + "49283963998703610290433733459893326289687463262782274915344363512372589485657"
      + "48195657207507439608336200760270250380693420228805822313533425874173983951784"
      + "19942267127718499461451487305894610452026399498022751973735223213703884630791"
      + "36443897509837456699480735485630158187049187185469933185484083189896569511896"
      + "19552689905200621756376700329095564065679677008736259746819636397699129661717"
      + "51451741230791738152076829821938949915850631491860811884643073657107050241912"
      + "96560764506852801118753295116070873945704245033781511673178904966217353776689");

  private final BigInteger exponent = new BigInteger("65537");

  @Test(expected = IllegalArgumentException.class)
  public void testCombine() throws Exception {
    ServerCryptoModule module1 = new SoftwareServerCryptoModule(new SecureRandom());
    ServerCryptoModule module2 = new SoftwareServerCryptoModule(new SecureRandom());
    RSASharedKey key1 = new RSASharedKey(modulus, privateKey.subtract(BigInteger.TEN), exponent);
    RSASharedKey key2 = new RSASharedKey(modulus, BigInteger.TEN, exponent);
    module1.setupServer(new KeyShares(key1, null, BigInteger.ONE, null));
    module2.setupServer(new KeyShares(key2, null, BigInteger.ONE, null));
    ThresholdRSAJWTTokenGenerator gen1 = new ThresholdRSAJWTTokenGenerator(module1);
    ThresholdRSAJWTTokenGenerator gen2 = new ThresholdRSAJWTTokenGenerator(module2);
    Map<String, Attribute> map = new HashMap<>();
    map.put("userLT42", new Attribute("true"));

    String token1 = gen1.generateToken(map);
    String token2 = gen2.generateToken(map);
    JWTUtil.combineTokens(Arrays.asList(token1, token2), modulus);
    fail();
  }
}
