package eu.olympus.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import eu.olympus.TestParameters;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeDefinition;
import eu.olympus.model.AttributeDefinitionString;
import eu.olympus.model.OPRFResponse;
import eu.olympus.model.PabcPublicParameters;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.PabcIdPImpl;
import eu.olympus.server.rest.AuthenticationFilter;
import eu.olympus.server.rest.PabcIdPServlet;
import eu.olympus.server.rest.RESTIdPServer;
import eu.olympus.util.multisign.MSverfKey;
import eu.olympus.util.psmultisign.PSverfKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.codec.binary.Base64;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.miracl.core.BLS12461.ECP;
import org.miracl.core.BLS12461.FP12;
import org.mockito.ArgumentCaptor;

public class TestPabcIdpRESTConnection {

    private static RESTIdPServer server = new RESTIdPServer();
    private static final String url = "http://127.0.0.1:8766";
    private static final String fp12String =
        "CCX3MY6l5x691jSy" + "NJKM8Q3BKGPiWJQt8zYkhATkkYNT7of" + "4OBnhQJdGxU3Tf1gQ+pprdhTI57mMHQ0rcnrycDqG8QuDYc11oh0+cu" + "KFR01XWojvSGGcU+FLzM7wpWNmKG1qI4iVW/vyUzoK6Xxj1c5po+kG7"
            + "hMZe3NEeAzzXhbTZUUjydnQaTGG2iKo2/rwMM3EvbcX3HVG8VlK2mqq" + "usVYyKKRIRNdbLdJLmK/EFwGMFAOIsJR8hlk8dZQS5dUdjC4uUk1dCT" + "dkieiII21MBSoTzwavllqooJ0ITnWJBXtdxJpnoU1lBQJIzSQT+gIq5"
            + "PxLYcmuANfxEv8Tpf9ayqDjTr0GWHNAxMYYV5gP0RrLv96gEOYc98W7" + "rS8GE6HrKUJqrkW+JTAUzHbgCd5+a61sDT+M/qUExZxrINT+JPVXaio" + "TUwvHs6PiykYsnJUJV6jHpdty0skbJ0rC4vWxPlcX8pB6MVhqeokKd0"
            + "0Q6on125OUtq5LgV5RgSFO9i2c8PbCvakUx/UFr8fdD/Jrf3JWOmfYQ" + "gf/Cxv86hovCepIs9rvs0wbprmEKvsdLJlVnjRnhtvfSKTjQnUnMph9" + "KX6Y2y6OFy02aNfjt0J7REB0VidQJKK/74gEHMB3mbmi3ChqqVaRU5l"
            + "a2J5OHzhSFhoZyIF/5VckCpyJiiV8vlLNDVKzglIJ1LyCepVeJO3rYj" + "tK+bqSSTs4pxE5C8n2TzPpHcv4ZO3crP4qIzWbSEAdRde+YXQUw3fOc" + "tSrgmBd+mPnwwgDotTsuOCztaMFHjttwHYvFUWVbYWwQEIWDW9qVaDM"
            + "in/IB0AjklFyzHr7w9gN2GBS0vQOS4Zn0gMlTbLbdHc+aVxVDp28zo7" + "Yz4zsNM9z3XeWm6/1L7wawqxQhM7FdSiZInyDzqU0kRubYGXva2e5CZ" + "i";
    private static final FP12 fp12 = FP12.fromBytes(Base64.decodeBase64(fp12String));
    private static final String publicParamString = "CAMSTAoyZXUub2x5b" + "XB1cy51dGlsLnBhaXJpbmdCTFM0NjEuUGFpcmluZ0J1aWxkZXJCTFM0" + "NjESC05hdGlvbmFsaXR5EgNBZ2USBE5hbWU=";

    private static final String psVerfKeyString = "CnoKeAo6EisbfOFyTuo" + "KozbyRISSwM85o5IXfiYZltcKGwoHoVFoHkBXJvnjn8YDczF/nZ8sdu" + "/8QpHsMZX4IhI6B7/noK3X0V5VAZ7cHLJNypLqZWxSgqwMKDwj7Yk7k"
        + "9L7j4Dk9S1u5zf2h3t5dQO04KT3111w1baUBRJ6CngKOhLrSyt1mP/V" + "9WdMeO9EOSxLNKSGARwEHyktfSMVtoeDp9vMXNkUPJi70CV82k0rhF/" + "3lFllvfuhFlQSOgk9TB/91EjG93BwdeZBKWDTkV3lhGGGCU2Lon4goo"
        + "7Jmu4E0yAsy3Cw45/nCXziiu/l5vBiXm9/j68aegp4CjoQfH7QJG1AX" + "oKkLQ0d7jWqFKV3eXpvGa7MiDB2miyW8y/SXxnT/ANYrLboa9YuZMQz" + "UAL1F8MXI9b6EjoJlBYVWdBNKysboy8Ii4+ioiFmfTY4FlRSIZwLIj3"
        + "V0gqscd0xjSSQKFxoBMtIe6oIGI4+eT/MvGBQIoEBCgNOb3cSegp4Cj" + "oABFx2HPX7IrN/u40TelnmU8QcMvCL4iiWmB3Pw2hq3eeBB8L+9ycKu" + "9Xrl0pDCEpeKGNKcb4XCJwfEjoBaQxyimDo/Q/Q8j4fiWz/+DYcTF9a"
        + "BlCxz8NMg4j9do2La6juzzckAcK22K23wzdxR4/ySjF2IAjOIoEBCgN" + "BZ2USegp4CjoQ1TdDVXwg4HowwLLNwo3dhvs8BpC6EvUHKQQKb3eBwh" + "eajbWFrHWcciBqILv/fyWKzSMZ0STBiY+1EjoE//2Jqk0zpzJt10Vg2"
        + "IZ/EZMhIPeVf21HfWGcTCEHuwYQEChVu4lrwRRZA7BbzXvUP0l9y3YS" + "QjhnIoIBCgROYW1lEnoKeAo6AzuLurQtXjxmt9nHOisR7THToYYnL/G" + "vqh43HAHdpwv75iO1QtORycj7UL4vIAJop8VuvE+eAWkKoRI6BBMy5B"
        + "G+qKntrFM5Z4k2pR7ToSp3zH4UYCKDNcZhXpiy0IjqpVG/4dGrciQY6" + "x/gepIjOKl8ROOSrA==";

    private static PabcIdPImpl idp;


    private static ArgumentCaptor<String> userCaptor;
    private static ArgumentCaptor<byte[]> sigCaptor;
    private static ArgumentCaptor<byte[]> oldSigCaptor;
    private static ArgumentCaptor<Long> longCaptor;
    private static ArgumentCaptor<Long> saltCaptor;
    private static ArgumentCaptor<PublicKey> publickeyCaptor;


    private static PabcIdPImpl mockIdp() throws Exception {
        PabcIdPImpl idp = mock(PabcIdPImpl.class);
        HashMap<String, Attribute> attr = new HashMap<String, Attribute>();
        attr.put("name", new Attribute("John"));
        AttributeDefinition def = new AttributeDefinitionString("Name", "Name", 1, 16);
        Set<AttributeDefinition> defs = new HashSet<>();
        defs.add(def);

        doReturn(true).when(idp).startRefresh();
        doReturn(new OPRFResponse(fp12, "ssid", "session")).when(idp).performOPRF(anyString(), anyString(), any(), anyString(), anyString());
        doReturn("reply".getBytes()).when(idp).finishRegistration(anyString(), any(), any(), any(), anyLong(), anyString());
        when(idp.getCertificate()).thenReturn(TestParameters.getRSA1Cert()).thenThrow(new RuntimeException());
        doReturn(TestParameters.getRSA1Cert()).when(idp).getCertificate();
        doReturn(true).when(idp).addAttributes(anyString(), any(), anyLong(), any(), anyString());
        doReturn(attr).when(idp).getAllAttributes(anyString(), any(), anyLong(), any());
        doReturn(true).when(idp).deleteAttributes(anyString(), any(), anyLong(), any(), any());
        doReturn(true).when(idp).deleteAccount(anyString(), any(), anyLong(), any());
        doReturn("response".getBytes()).when(idp).changePassword(anyString(), any(), any(), any(), any(), anyLong());
        doReturn("credential").when(idp).getCredentialShare(anyString(), any(), anyLong(), any(), anyLong());
        doReturn(new PSverfKey(Base64.decodeBase64(psVerfKeyString))).when(idp).getPabcPublicKeyShare();
        doReturn(new PabcPublicParameters(defs, publicParamString)).when(idp).getPabcPublicParam();

        return idp;
    }

    @BeforeClass
    public static void startServer() throws Exception {
        idp = mockIdp();

        server.setIdP(idp);

        List<String> types = new ArrayList<>();
        types.add(PabcIdPServlet.class.getCanonicalName());
        types.add(AuthenticationFilter.class.getCanonicalName());

        server.start(8766, types, 8767, null, null, null);
    }

    @AfterClass
    public static void stopServer() throws Exception {
        server.stop();
    }

    @Test
    public void testPerformOPRFMFA() throws Exception {
        PabcIdPRESTConnection connection = new PabcIdPRESTConnection(url, "token", 0, 100000);
        OPRFResponse response = connection.performOPRF("ssid", "username", ECP.generator(), "", "NONE");
        verify(idp, times(1)).performOPRF(anyString(), anyString(), any(), anyString(), anyString());
        assertEquals("ssid", response.getSsid());
        byte[] bytes = new byte[696];
        response.getY().toBytes(bytes);
        assertEquals(fp12String, Base64.encodeBase64String(bytes));
    }


    @Test
    public void TestObtainCredential() throws Exception {
        PabcIdPRESTConnection connection = new PabcIdPRESTConnection(url, "token", 0, 100000);
        String credential = connection.getCredentialShare("user", "session".getBytes(), 0, "some-pretty-long-and-winding-share".getBytes(), 1000);
        verify(idp, times(1)).getCredentialShare(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture(), longCaptor.capture());
        assertEquals("user", userCaptor.getValue());
        assertEquals(Long.valueOf(0), saltCaptor.getValue());
        assertEquals("some-pretty-long-and-winding-share", new String(sigCaptor.getValue()));
        assertEquals(Long.valueOf(1000), longCaptor.getValue());
        assertEquals("credential", credential);
    }

    @Test
    public void TestGetPabcPublicKey() throws Exception {
        PabcIdPRESTConnection connection = new PabcIdPRESTConnection(url, "token", 0, 100000);
        MSverfKey key = connection.getPabcPublicKeyShare();
        verify(idp, times(1)).getPabcPublicKeyShare();
        assertEquals(psVerfKeyString, Base64.encodeBase64String(key.getEncoded()));
        verify(idp,times(1)).getPabcPublicKeyShare();
    }

    @Test
    public void TestGetPabcPublicParam() throws Exception {
        PabcIdPRESTConnection connection = new PabcIdPRESTConnection(url, "token", 0, 100000);
        PabcPublicParameters params = connection.getPabcPublicParam();
        verify(idp, times(1)).getPabcPublicParam();
        assertEquals(publicParamString, params.getEncodedSchemePublicParam());
    }

    @Test(expected = OperationFailedException.class)
    public void TestGetPabcPublicKeyFails() throws Exception {
        PabcIdPRESTConnection connection = new PabcIdPRESTConnection(url, "token", 0, 100000);
        doThrow(new RuntimeException()).when(idp).getPabcPublicKeyShare();
        connection.getPabcPublicKeyShare();
    }

    @Test(expected = OperationFailedException.class)
    public void TestGetPabcPublicParamFails() throws Exception {
        PabcIdPRESTConnection connection = new PabcIdPRESTConnection(url, "token", 0, 100000);
        doThrow(new RuntimeException()).when(idp).getPabcPublicParam();
        connection.getPabcPublicParam();
    }

    @Test
    public void testGetPublicKey() throws Exception {
        PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
        Certificate cert = connection.getCertificate();
        verify(idp, times(1)).getCertificate();
        assertEquals(cert, TestParameters.getRSA1Cert());
        doThrow(new RuntimeException()).when(idp).getCertificate();
        try {
            connection.getCertificate();
            fail();
        } catch (Exception e){
            assertTrue(e instanceof RuntimeException);
        }
    }

    @Test
    public void testGetAllAttributes() throws Exception {
        PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
        Map<String, Attribute> attributes = connection.getAllAttributes("username", "session".getBytes(), 200, "sig".getBytes());
        verify(idp, times(1)).getAllAttributes(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture());
        assertEquals("username", userCaptor.getValue());
        assertEquals("sig", new String(sigCaptor.getValue()));
        assertEquals(Long.valueOf(200), saltCaptor.getValue());
        assertEquals(new Attribute("John"), attributes.get("name"));
        assertEquals(1, attributes.size());
    }

    @Test
    public void testDeleteAttributes() throws Exception {
        PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
        List<String> attributes = new ArrayList<String>();
        attributes.add("name");
        assertTrue(connection.deleteAttributes("username", "session".getBytes(), 300, "signature".getBytes(), attributes));
        verify(idp, times(1)).deleteAttributes(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture(), any());
        assertEquals("username", userCaptor.getValue());
        assertEquals("signature", new String(sigCaptor.getValue()));
        assertEquals(Long.valueOf(300), saltCaptor.getValue());
        assertEquals("name", attributes.get(0));
        assertEquals(1, attributes.size());
    }

    @Test
    public void testDeleteAccount() throws Exception {
        PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
        assertTrue(connection.deleteAccount("user", "session".getBytes(), 10, "signature".getBytes()));
        verify(idp, times(1)).deleteAccount(userCaptor.capture(), any(), saltCaptor.capture(), sigCaptor.capture());
        assertEquals("user", userCaptor.getValue());
        assertEquals("signature", new String(sigCaptor.getValue()));
        assertEquals(Long.valueOf(10), saltCaptor.getValue());
    }

    @Test
    public void testChangePassword() throws Exception {
        PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
        byte[] response = connection.changePassword("username", "session".getBytes(), TestParameters.getECPublicKey2(), "oldsignature".getBytes(), "newsignature".getBytes(), 100);
        verify(idp, times(1)).changePassword(userCaptor.capture(), any(), publickeyCaptor.capture(), sigCaptor.capture(), oldSigCaptor.capture(), anyLong());
        assertEquals("username", userCaptor.getValue());
        assertEquals(TestParameters.getECPublicKey2(), publickeyCaptor.getValue());
        assertEquals("oldsignature", new String(sigCaptor.getValue()));
        assertEquals("newsignature", new String(oldSigCaptor.getValue()));
        assertEquals("response", new String(response));
    }

    @Test (expected = RuntimeException.class)
    public void testAddMasterShare() {
        PestoIdPRESTConnection connection = new PestoIdPRESTConnection(url, "token", 0, 100000);
        connection.addMasterShare("ssid", "some-pretty-long-and-winding-share".getBytes());
        fail();
    }

    @Before
    public void beforeEach() {
        userCaptor = ArgumentCaptor.forClass(String.class);
        saltCaptor = ArgumentCaptor.forClass(Long.class);
        longCaptor = ArgumentCaptor.forClass(Long.class);
        sigCaptor = ArgumentCaptor.forClass(byte[].class);
        oldSigCaptor = ArgumentCaptor.forClass(byte[].class);
        publickeyCaptor = ArgumentCaptor.forClass(PublicKey.class);
    }
}
