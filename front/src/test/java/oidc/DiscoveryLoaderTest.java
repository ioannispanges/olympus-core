package oidc;

import lombok.SneakyThrows;
import oidc.model.DiscoveryLoader;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Test;

public class DiscoveryLoaderTest {

    @SneakyThrows
    @Test
    public void canLoadFileCorrectly() {
        DiscoveryLoader discoveryLoader =
            new DiscoveryLoader("src/test/resources/test-openid-configuration-discovery.json");
        JSONObject out = discoveryLoader.out();
        Assert.assertNotNull(out);
        Assert.assertEquals(out.get("issuer").toString(),"test");
    }
}
