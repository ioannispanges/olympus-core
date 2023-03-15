package eu.olympus.oidc.server.storage;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeType;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.oidc.TestParameters;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SqlitePestoDatabaseTest {

    private SqlitePestoDatabase db;

    private SqlitePestoDatabase failingDb() throws SQLException {
        Connection mock = mock(Connection.class);
        doThrow(SQLException.class).when(mock).prepareStatement(anyString());
        doThrow(SQLException.class).when(mock).prepareStatement(anyString());
        return new SqlitePestoDatabase(mock);
    }

    @Before
    public void setup() throws SetupException, OperationFailedException {
        // Remove previous database
        new File("src/test/resources/db").delete();
        // Create clean database
        String pathToDb = SqlitePestoDatabase.createDatabase("src/test/resources/db");
        db = new SqlitePestoDatabase(SqlitePestoDatabase.constructConnection(pathToDb));
        db.addUser("test", TestParameters.getECPublicKey2(),1000L);
        db.clearFailedAuthAttempts("test");
        db.clearFailedMFAAttempts("test");
    }

    @Test(expected = SetupException.class)
    public void testConstructorBadUrl() throws SetupException {
        SqlitePestoDatabase.constructConnection("badUrl");
    }

    @Test(expected = OperationFailedException.class)
    public void testCreateDatabaseBadUrl() throws OperationFailedException {
        SqlitePestoDatabase.createDatabase("/src/test/resources/does/not/exist/db");
    }

    @Test
    public void testAddUser() throws OperationFailedException {
        db.addUser("username", TestParameters.getECPublicKey2(),1000L);
    }

    @Test(expected = OperationFailedException.class)
    public void testAddUserDbException() throws OperationFailedException, SQLException {
        failingDb().addUser("username", TestParameters.getECPublicKey2(),1000L);
    }

    @Test
    public void testGetUserKey() throws OperationFailedException {
        db.addUser("aUsername", TestParameters.getRSAPublicKey1(),1000L);
        PublicKey key = db.getUserKey("aUsername");
        Assert.assertEquals(TestParameters.getRSAPublicKey1(), key);
    }

    @Test
    public void testGetUserKeyECKey() throws OperationFailedException {
        db.addUser("ecUsername", TestParameters.getECPublicKey2(),1000L);
        PublicKey key = db.getUserKey("ecUsername");
        Assert.assertEquals(TestParameters.getECPublicKey2(), key);
    }

    @Test(expected = OperationFailedException.class)
    public void testGetUserKeyDbException() throws OperationFailedException, SQLException {
        failingDb().getUserKey("username");
    }

    @Test
    public void testReplaceUserKey() throws OperationFailedException {
        db.addUser("replacingUsername", TestParameters.getRSAPublicKey1(),1000L);
        db.replaceUserKey("replacingUsername", TestParameters.getRSAPublicKey2(),3000L);
        PublicKey key = db.getUserKey("replacingUsername");
        long salt = db.getLastSalt("replacingUsername");
        Assert.assertEquals(TestParameters.getRSAPublicKey2(), key);
        Assert.assertEquals(3000L,salt);
    }

    @Test(expected = OperationFailedException.class)
    public void testReplaceUserKeyDbException() throws OperationFailedException, SQLException {
        failingDb().replaceUserKey("username", TestParameters.getECPublicKey2(),1000L);
    }

    @Test
    public void testGetSalt() throws OperationFailedException {
        long salt = db.getLastSalt("test");
        Assert.assertEquals(1000L,salt);
    }

    @Test(expected = OperationFailedException.class)
    public void testGetSaltDbException() throws OperationFailedException, SQLException {
        failingDb().getLastSalt("username");
    }
    @Test
    public void testSetSalt() throws OperationFailedException {
        db.addUser("aTest", TestParameters.getRSAPublicKey1(),1000L);
        db.setSalt("aTest",2000L);
        long salt = db.getLastSalt("aTest");
        Assert.assertEquals(2000L,salt);
    }
    @Test(expected = OperationFailedException.class)
    public void testSetSaltDbException() throws OperationFailedException, SQLException {
        failingDb().setSalt("aTest",2000L);
    }
    @Test
    public void testHasUser() throws OperationFailedException {
        db.hasUser("test");
        Assert.assertTrue(db.hasUser("test"));
        Assert.assertFalse(db.hasUser("invalidUsername"));
    }
    @Test(expected = OperationFailedException.class)
    public void testHasUserDbException() throws OperationFailedException, SQLException {
        failingDb().hasUser("username");
    }
    @Test
    public void testDeleteUser() throws OperationFailedException {
        Assert.assertTrue(db.hasUser("test"));
        Assert.assertTrue(db.deleteUser("test"));
        Assert.assertFalse(db.hasUser("test"));
    }
    @Test()
    public void testDeleteUserDbException() throws OperationFailedException, SQLException {
        Assert.assertFalse(failingDb().deleteUser("username"));
    }
    @Test
    public void testAssignMFASecret() throws OperationFailedException {
        db.assignMFASecret("test","type","secret");
    }
    @Test(expected = OperationFailedException.class)
    public void testAssignMFASecretDbException() throws OperationFailedException, SQLException {
        failingDb().assignMFASecret("test","type","secret");
    }
    @Test
    public void testGetMFASecret() throws OperationFailedException {
        db.assignMFASecret("test","type","secret");
        Map<String, MFAInformation> res = db.getMFAInformation("test");
        Assert.assertEquals(res.size(),1);
        Assert.assertNotNull(res.get("type"));
        Assert.assertEquals("secret",res.get("type").getSecret());
    }

    @Test(expected = OperationFailedException.class)
    public void testGetMFAInformationDbException() throws OperationFailedException, SQLException {
        failingDb().getMFAInformation("test");
    }
    @Test
    public void testActivateMFA() throws OperationFailedException {
        db.assignMFASecret("test","type","secret");
        db.activateMFA("test","type");
        Map<String, MFAInformation> res = db.getMFAInformation("test");
        Assert.assertEquals(res.size(),1);
        Assert.assertNotNull(res.get("type"));
        Assert.assertTrue(res.get("type").isActivated());
    }
    @Test(expected = OperationFailedException.class)
    public void testActivateMFADbException() throws OperationFailedException, SQLException {
        failingDb().activateMFA("test","type");
    }
    @Test
    public void testDeleteMFA() throws OperationFailedException {
        db.deleteMFA("test","type");
        Map<String, MFAInformation> res = db.getMFAInformation("test");
        Assert.assertEquals(res.size(),0);
        Assert.assertNull(res.get("type"));
    }

    @Test(expected = OperationFailedException.class)
    public void testDeleteMFADbException() throws OperationFailedException, SQLException {
        failingDb().deleteMFA("test","type");
    }
    @Test
    public void testFailedAuthAttempt() throws OperationFailedException {
        db.failedAuthAttempt("test");
        int first = db.getNumberOfFailedAuthAttempts("test");
        Assert.assertEquals(1,first);

        db.failedAuthAttempt("test");
        int second = db.getNumberOfFailedAuthAttempts("test");
        Assert.assertEquals(2,second);
    }
    @Test(expected = OperationFailedException.class)
    public void testFailedAuthAttemptDbException() throws OperationFailedException, SQLException {
        failingDb().failedAuthAttempt("username");
    }
    @Test
    public void testClearFailedAuthAttempts() throws OperationFailedException {
        db.failedAuthAttempt("test");
        int res = db.getNumberOfFailedAuthAttempts("test");
        Assert.assertNotEquals(0,res);

        db.clearFailedAuthAttempts("test");
        res = db.getNumberOfFailedAuthAttempts("test");
        Assert.assertEquals(0,res);
    }
    @Test(expected = OperationFailedException.class)
    public void tesGetNumberOfFailedAuthAttemptsDbException() throws OperationFailedException, SQLException {
        failingDb().getNumberOfFailedAuthAttempts("username");
    }
    @Test(expected = OperationFailedException.class)
    public void testClearFailedAuthAttemptsDbException() throws OperationFailedException, SQLException {
        failingDb().clearFailedAuthAttempts("username");
    }
    @Test
    public void testGetLastAuthAttempt() throws OperationFailedException {
        long time = System.currentTimeMillis();
        db.failedAuthAttempt("test");
        long res = db.getLastAuthAttempt("test");
        Assert.assertTrue(time - res < 1000);
    }
    @Test
    public void testGetLastAuthAttemptNoAttempts() throws OperationFailedException {
        Assert.assertEquals(0,db.getLastAuthAttempt("hasNeverAuthorized"));
    }
    @Test(expected = OperationFailedException.class)
    public void testGetLastAuthAttemptDbException() throws OperationFailedException, SQLException {
        failingDb().getLastAuthAttempt("username");
    }
    @Test
    public void testFailedMFAAttempt() throws OperationFailedException {
        db.failedMFAAttempt("test");
        int first = db.getNumberOfFailedMFAAttempts("test");
        Assert.assertEquals(1,first);

        db.failedMFAAttempt("test");
        int second = db.getNumberOfFailedMFAAttempts("test");
        Assert.assertEquals(2,second);
    }
    @Test
    public void testGetLastMFAAttemptNoAttempts() throws OperationFailedException {
        Assert.assertEquals(0,db.getNumberOfFailedMFAAttempts("hasNeverAuthorized"));
    }
    @Test(expected = OperationFailedException.class)
    public void testGetFailedMFAAttemptDbException() throws OperationFailedException, SQLException {
        failingDb().getNumberOfFailedMFAAttempts("username");
    }
    @Test(expected = OperationFailedException.class)
    public void testFailedMFAAttemptDbException() throws OperationFailedException, SQLException {
        failingDb().failedMFAAttempt("username");
    }
    @Test
    public void testClearFailedMFAAttempts() throws OperationFailedException {
        db.failedMFAAttempt("test");
        int res = db.getNumberOfFailedMFAAttempts("test");
        Assert.assertNotEquals(0,res);

        db.clearFailedMFAAttempts("test");
        res = db.getNumberOfFailedMFAAttempts("test");
        Assert.assertEquals(0,res);
    }
    @Test(expected = OperationFailedException.class)
    public void testClearFailedMFAAttemptsDbException() throws OperationFailedException, SQLException {
        failingDb().clearFailedMFAAttempts("username");
    }
    @Test
    public void testGetLastMFAAttempt() throws OperationFailedException {
        long time = System.currentTimeMillis();
        db.failedMFAAttempt("test");
        long res = db.getLastMFAAttempt("test");
        Assert.assertTrue(time - res < 1000);
    }
    @Test(expected = OperationFailedException.class)
    public void testGetLastMFAAttemptDbException() throws OperationFailedException, SQLException {
        failingDb().getLastMFAAttempt("username");
    }
    @Test
    public void testAddAttributeInt() throws OperationFailedException {
        db.addAttribute("test","age",new Attribute(24, AttributeType.INTEGER));
    }
    @Test
    public void testAddAttributeDate() throws OperationFailedException {
        db.addAttribute("test","aDate",new Attribute(new Date(), AttributeType.DATE));
    }
    @Test
    public void testAddAttributeString() throws OperationFailedException {
        db.addAttribute("test","aString",new Attribute("string", AttributeType.STRING));
    }
    @Test
    public void testAddAttributeBool() throws OperationFailedException {
        db.addAttribute("test","aBool",new Attribute(true, AttributeType.BOOLEAN));
    }
    @Test(expected = OperationFailedException.class)
    public void testAddAttributeDbException() throws OperationFailedException, SQLException {
        failingDb().addAttribute("test","aBool",new Attribute(true, AttributeType.BOOLEAN));
    }
    @Test
    public void testGetAttributes() throws OperationFailedException {
        Attribute age = new Attribute(24, AttributeType.INTEGER);
        Attribute date = new Attribute(new Date(), AttributeType.DATE);
        Attribute string = new Attribute("string", AttributeType.STRING);
        Attribute bool = new Attribute(true, AttributeType.BOOLEAN);
        db.addAttribute("test","aDate",date);
        db.addAttribute("test","anInt",age);
        db.addAttribute("test","aString",string);
        db.addAttribute("test","aBool",bool);

        Map<String, Attribute> res = db.getAttributes("test");
        Assert.assertEquals(age,res.get("anInt"));
        Assert.assertEquals(date,res.get("aDate"));
        Assert.assertEquals(string,res.get("aString"));
        Assert.assertEquals(bool,res.get("aBool"));
    }
    @Test(expected = OperationFailedException.class)
    public void testGetAttributesDbException() throws OperationFailedException, SQLException {
        failingDb().getAttributes("username");
    }
    @Test
    public void testAddAttributes() throws OperationFailedException {
        Attribute age = new Attribute(24, AttributeType.INTEGER);
        Attribute date = new Attribute(new Date(), AttributeType.DATE);
        Attribute string = new Attribute("string", AttributeType.STRING);
        Attribute bool = new Attribute(true, AttributeType.BOOLEAN);

        Map<String, Attribute> attrs = new HashMap<>();
        attrs.put("age",age);
        attrs.put("aDate",date);
        attrs.put("aString",string);
        attrs.put("aBool",bool);

        db.addAttributes("test",attrs);

        Map<String, Attribute> res = db.getAttributes("test");
        Assert.assertEquals(age,res.get("age"));
        Assert.assertEquals(date,res.get("aDate"));
        Assert.assertEquals(string,res.get("aString"));
        Assert.assertEquals(bool,res.get("aBool"));
    }
    @Test(expected = OperationFailedException.class)
    public void testAddAttributesDbException() throws OperationFailedException, SQLException {
        failingDb().getAttributes("username");
    }
    @Test
    public void testDeleteAttribute() throws OperationFailedException {
        Attribute age = new Attribute(24, AttributeType.INTEGER);
        db.addAttribute("test","anInt",age);

        Map<String, Attribute> res = db.getAttributes("test");
        Assert.assertEquals(age,res.get("anInt"));

        db.deleteAttribute("test","anInt");

        res = db.getAttributes("test");
        Assert.assertNull(res.get("anInt"));
    }
    @Test()
    public void testDeleteAttributeDbException() throws OperationFailedException, SQLException {
        Assert.assertFalse(failingDb().deleteAttribute("username","test"));
    }
    @Test
    public void testSetKeyShare() throws OperationFailedException {
        byte[] share = "share".getBytes(StandardCharsets.UTF_8);
        db.setKeyShare(1,share);
        byte[] res = db.getKeyShare(1);
        Assert.assertArrayEquals(share, res);
    }
    @Test(expected = OperationFailedException.class)
    public void testSetKeyShareDbException() throws OperationFailedException, SQLException {
        failingDb().setKeyShare(1,new byte[325]);
    }
    @Test(expected = OperationFailedException.class)
    public void testGetKeyShareDbException() throws OperationFailedException, SQLException {
        failingDb().getKeyShare(1);
    }
    @Test
    public void testSetKeyDigest() throws OperationFailedException {
        byte[] share = "share".getBytes(StandardCharsets.UTF_8);
        db.setKeyDigest(share);
        byte[] res = db.getKeyDigest();
        Assert.assertEquals(share.length, res.length);
        for (int i = 0; i < share.length; i++) {
            Assert.assertEquals(share[i], res[i]);
        }
    }
    @Test(expected = OperationFailedException.class)
    public void testSetKeyDigestDbException() throws OperationFailedException, SQLException {
        failingDb().getKeyDigest();
    }
}
