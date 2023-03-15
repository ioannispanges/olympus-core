package eu.olympus.oidc.server.storage;

import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.model.Attribute;
import eu.olympus.model.AttributeType;
import eu.olympus.model.MFAInformation;
import eu.olympus.model.SerializedKey;
import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.model.exceptions.SetupException;
import eu.olympus.protos.serializer.PabcSerializer;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.rest.PabcIdPServlet;
import eu.olympus.util.KeySerializer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.SerializationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SqlitePestoDatabase implements PestoDatabase {


    private static final Logger logger = LoggerFactory.getLogger(PabcIdPServlet.class);
    private Connection connection;

    public SqlitePestoDatabase(Connection connection) {
        this.connection = connection;
        logger.info("Connection succeeded");
    }

    public static String createDatabase(String fileName) throws OperationFailedException {
        String url = "jdbc:sqlite:" + fileName;
        try (Connection conn = DriverManager.getConnection(url)) {
            if (conn != null) {
                DatabaseMetaData meta = conn.getMetaData();
                logger.info("The driver name is " + meta.getDriverName());
                logger.info("A new database has been created.");

                Statement stmt = conn.createStatement();
                String createUserTableSql = "CREATE TABLE IF NOT EXISTS users" + "(username TEXT," + "salt INTEGER," + "publicKey TEXT," + "lastAuthAttempt INTEGER," + "lastMFAAttempt INTEGER,"
                    + "numberOfAuthAttempts INTEGER," + "numberOfMFAAttempts INTEGER)";
                stmt.execute(createUserTableSql);


                stmt = conn.createStatement();
                String createAttributeTableSql = "CREATE TABLE IF NOT EXISTS attributes" + "(username TEXT," + "type TEXT," + "attr BLOB)";
                stmt.execute(createAttributeTableSql);


                stmt = conn.createStatement();
                String createKeyShareTableSql = "CREATE TABLE IF NOT EXISTS idpKeyShares" + "(idp INTEGER," + "keyShare BLOB)";
                stmt.execute(createKeyShareTableSql);

                stmt = conn.createStatement();
                String createKeyDigestTableSql = "CREATE TABLE IF NOT EXISTS keyDigest" + "(digest BLOB)";
                stmt.execute(createKeyDigestTableSql);


                stmt = conn.createStatement();
                String createMFAInformationTableSql = "CREATE TABLE IF NOT EXISTS mfaInformation" + "(username TEXT," + "type TEXT," + "mfaInfo BLOB)";
                stmt.execute(createMFAInformationTableSql);


            }
        } catch (SQLException e) {
            logger.error("Failed to connect to database", e);
            throw new OperationFailedException("Failed to connect to database", e);
        }
        return url;
    }

    public static Connection constructConnection(String url) throws SetupException {
        // SQLite connection string
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(url);
        } catch (SQLException e) {
            logger.error("Failed to connect to database", e);
            throw new SetupException("Failed to connect to database", e);
        }
        return conn;
    }


    @Override
    public void addUser(String username, PublicKey key, long salt) throws OperationFailedException {
        String query = "INSERT INTO users(username,salt," + "publicKey,lastAuthAttempt," + "lastMFAAttempt,numberOfAuthAttempts,numberOfMFAAttempts) " + "VALUES (?,?,?,NULL,NULL,NULL,NULL)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setLong(2, salt);
            SerializedKey serializedKey = KeySerializer.serialize(key);
            String keyEncoded = Base64.encodeBase64String(serializedKey.getBytes());
            stmt.setString(3, keyEncoded);
            stmt.execute();
            logger.info("User was successfully added: " + username);
        } catch (SQLException e) {
            logger.error("Failed to create user", e);
            throw new OperationFailedException("Failed to create user", e);
        }
    }

    @Override
    public PublicKey getUserKey(String username) throws OperationFailedException {
        String query = "SELECT publicKey FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if(resultSet.isClosed()){
                throw new OperationFailedException("Failed to retrieve public key for user. User was not found");
            }
            byte[] res = Base64.decodeBase64(resultSet.getString("publicKey"));
            SerializedKey serializedKey = new SerializedKey(res);
            return (PublicKey) KeySerializer.deSerialize(serializedKey);
        } catch (SQLException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            logger.error("Failed to retrieve public key for user", e);
            throw new OperationFailedException("Failed to retrieve public key for user", e);
        }
    }

    @Override
    public long getLastSalt(String username) throws OperationFailedException {
        String query = "SELECT salt FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            return resultSet.getLong("salt");
        } catch (SQLException e) {
            logger.error("Failed to retrieve salt for user", e);
            throw new OperationFailedException("Failed to retrieve salt for user", e);
        }
    }

    @Override
    public void setSalt(String username, long salt) throws OperationFailedException {
        String query = "UPDATE users SET salt=? WHERE username =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setLong(1, salt);
            stmt.setString(2, username);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to set salt for user", e);
            throw new OperationFailedException("Failed to set salt for user", e);
        }
    }

    @Override
    public void replaceUserKey(String username, PublicKey publicKey, long salt) throws OperationFailedException {
        String query = "UPDATE users SET publicKey=?, salt=? WHERE username =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            String keyEncoded = Base64.encodeBase64String(KeySerializer.serialize(publicKey).getBytes());
            stmt.setString(1, keyEncoded);
            stmt.setLong(2, salt);
            stmt.setString(3, username);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to replace public key for user", e);
            throw new OperationFailedException("Failed to replace public key for user", e);
        }
    }

    @Override
    public byte[] getKeyDigest() throws OperationFailedException {
        String query = "SELECT * FROM keyDigest";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            ResultSet resultSet = stmt.executeQuery();
            return Base64.decodeBase64(resultSet.getString("digest"));
        } catch (SQLException e) {
            logger.error("Failed to retrieve key digest", e);
            throw new OperationFailedException("Failed to retrieve key digest", e);
        }
    }

    @Override
    public void setKeyDigest(byte[] digest) throws OperationFailedException {
        String query = "REPLACE INTO keyDigest(digest) " + "VALUES (?)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, Base64.encodeBase64String(digest));
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to set key digest", e);
            throw new OperationFailedException("Failed to set key digest", e);
        }
    }

    @Override
    public void setKeyShare(int id, byte[] shares) throws OperationFailedException {
        String query = "REPLACE INTO idpKeyShares(idp,keyShare) " + "VALUES (?,?)";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, id);
            stmt.setString(2, Base64.encodeBase64String(shares));
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to set key share for idp", e);
            throw new OperationFailedException("Failed to set key share for idp", e);
        }
    }

    @Override
    public byte[] getKeyShare(int id) throws OperationFailedException {
        String query = "SELECT * FROM idpKeyShares WHERE idp = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, id);
            ResultSet resultSet = stmt.executeQuery();
            return Base64.decodeBase64(resultSet.getString("keyShare"));
        } catch (SQLException e) {
            logger.error("Failed to retrieve key share for idp", e);
            throw new OperationFailedException("Failed to retrieve key share for idp", e);
        }
    }

    @Override
    public boolean hasUser(String username) throws OperationFailedException {
        String query = "SELECT * FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            return resultSet.next();
        } catch (SQLException e) {
            logger.error("Failed to check if database has user", e);
            throw new OperationFailedException("Failed to check if database has user", e);
        }
    }

    @Override
    public Map<String, Attribute> getAttributes(String username) throws OperationFailedException {
        String query = "SELECT * FROM attributes WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            Map<String, Attribute> res = new HashMap<>();
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            while (resultSet.next()) {
                String type = resultSet.getString("type");
                byte[] attrByte = resultSet.getBytes("attr");
                PabcSerializer.Attribute parsedAttr = PabcSerializer.Attribute.parseFrom(attrByte);
                res.put(type, constructAttribute(parsedAttr));
            }
            return res;
        } catch (SQLException | InvalidProtocolBufferException e) {
            logger.error("Failed to retrieve attributes for user", e);
            throw new OperationFailedException("Failed to retrieve attributes for user", e);
        }
    }

    private Attribute constructAttribute(PabcSerializer.Attribute attribute) {
        Attribute newAttribute = new Attribute();
        switch (attribute.getType()) {
            case STRING:
                String string = new String(attribute.getObj().toByteArray(), StandardCharsets.UTF_8);
                newAttribute = new Attribute(string, AttributeType.STRING);
                break;
            case INTEGER:
                int integer = new BigInteger(attribute.getObj().toByteArray()).intValue();
                newAttribute = new Attribute(integer, AttributeType.INTEGER);
                break;
            case BOOLEAN:
                boolean bool = attribute.getObj().toByteArray()[0] != 0;
                newAttribute = new Attribute(bool, AttributeType.BOOLEAN);
                break;
            case DATE:
                Date date = new Date(bytesToLong(attribute.getObj().toByteArray()));
                newAttribute = new Attribute(date, AttributeType.DATE);
                break;
            default:
                break;
        }
        return newAttribute;
    }

    private static long bytesToLong(byte[] b) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

    @Override
    public void addAttributes(String username, Map<String, Attribute> attributes) throws OperationFailedException {
        for (Entry<String, Attribute> entry : attributes.entrySet()) {
            String key = entry.getKey();
            Attribute attr = entry.getValue();
            addAttribute(username, key, attr);
        }
    }

    @Override
    public void addAttribute(String username, String key, Attribute value) throws OperationFailedException {
        String query = "INSERT INTO attributes(username,type,attr) " + "VALUES (?,?,?)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, key);
            stmt.setBytes(3, value.toProto().toByteArray());
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to add attributes to user", e);
            throw new OperationFailedException("Failed to add attributes to user", e);
        }
    }

    @Override
    public boolean deleteAttribute(String username, String attributeName) throws OperationFailedException {
        String query = "DELETE FROM attributes WHERE username = ? AND type = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, attributeName);
            stmt.execute();
            return true;
        } catch (SQLException e) {
            logger.info("Failed to delete attribute", e);
            return false;
        }
    }

    @Override
    public boolean deleteUser(String username) throws OperationFailedException {
        String query = "DELETE FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.execute();
            return true;
        } catch (SQLException e) {
            logger.info("Failed to delete user", e);
            return false;
        }
    }

    @Override
    public void assignMFASecret(String username, String type, String secret) throws OperationFailedException {
        String query = "INSERT INTO mfaInformation(username,type,mfaInfo) " + "VALUES (?,?,?)";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            MFAInformation information = new MFAInformation(type, secret, System.currentTimeMillis(), false);

            stmt.setString(1, username);
            stmt.setString(2, type);
            stmt.setString(3, Base64.encodeBase64String(SerializationUtils.serialize(information)));
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to assign MFA secret to user", e);
            throw new OperationFailedException("Failed to assign MFA secret to user", e);
        }
    }

    @Override
    public Map<String, MFAInformation> getMFAInformation(String username) throws OperationFailedException {
        String query = "SELECT * FROM mfaInformation WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            Map<String, MFAInformation> result = new HashMap<>();
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            while (resultSet.next()) {
                String type = resultSet.getString("type");
                result.put(type, SerializationUtils.deserialize(Base64.decodeBase64(resultSet.getBytes("mfaInfo"))));
            }
            return result;
        } catch (SQLException e) {
            logger.error("Failed to retrieve MFA information for user", e);
            throw new OperationFailedException("Failed to retrieve MFA information for user", e);
        }
    }

    @Override
    public void activateMFA(String username, String type) throws OperationFailedException {
        String query = "SELECT * FROM mfaInformation WHERE username=? AND type=?";
        MFAInformation information;
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, type);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                information = SerializationUtils.deserialize(Base64.decodeBase64(resultSet.getBytes("mfaInfo")));
            } else {
                logger.info("The user did not have a MFAInformation of the given type: " + type);
                throw new OperationFailedException("The user did not have a MFAInformation of the given type: " + type);
            }
        } catch (SQLException e) {
            logger.error("Failed to activate MFAInformation for user", e);
            throw new OperationFailedException("Failed to activate MFAInformation for user", e);
        }

        information.setActivated(true);
        query = "UPDATE mfaInformation SET mfaInfo=? WHERE type =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, Base64.encodeBase64String(SerializationUtils.serialize(information)));
            stmt.setString(2, type);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to activate MFAInformation for user", e);
            throw new OperationFailedException("Failed to activate MFAInformation for user", e);
        }

    }

    @Override
    public void deleteMFA(String username, String type) throws OperationFailedException {
        String query = "DELETE FROM mfaInformation WHERE username = ? AND type = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.setString(2, type);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to delete MFA for user", e);
            throw new OperationFailedException("Failed to delete MFA for user", e);
        }
    }

    @Override
    public long getLastAuthAttempt(String username) throws OperationFailedException {
        String query = "SELECT lastAuthAttempt FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getLong("lastAuthAttempt");
            } else {
                return 0;
            }
        } catch (SQLException e) {
            logger.error("Failed to retrieve last authentication attempt for user", e);
            throw new OperationFailedException("Failed to retrieve last authentication attempt for user", e);
        }
    }

    @Override
    public int getNumberOfFailedAuthAttempts(String username) throws OperationFailedException {
        String query = "SELECT numberOfAuthAttempts FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("numberOfAuthAttempts");
            } else {
                return 0;
            }
        } catch (SQLException e) {
            logger.error("Failed to retrieve the number of failed authentication" + " attempts for user", e);
            throw new OperationFailedException("Failed to retrieve the number of failed authentication" + " attempts for user", e);
        }
    }

    @Override
    public void failedAuthAttempt(String username) throws OperationFailedException {
        String query = "SELECT numberOfAuthAttempts FROM users WHERE username = ?";
        int prevAttempts = 1;
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                prevAttempts += resultSet.getInt("numberOfAuthAttempts");
            }
        } catch (SQLException e) {
            logger.error("Failed to retrieve number of failed authentication attempts for user", e);
            throw new OperationFailedException("Failed to retrieve number of failed authentication attempts for user", e);
        }
        query = "UPDATE users SET numberOfAuthAttempts=?, lastAuthAttempt=? WHERE username =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setLong(1, prevAttempts);
            stmt.setLong(2, System.currentTimeMillis());
            stmt.setString(3, username);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to update number of failed authentication attempts for user", e);
            throw new OperationFailedException("Failed to update number of failed authentication attempts for user", e);
        }
    }

    @Override
    public void clearFailedAuthAttempts(String username) throws OperationFailedException {
        String query = "UPDATE users SET numberOfAuthAttempts=? WHERE username =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setLong(1, 0);
            stmt.setString(2, username);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to clear failed authentication attempts for user", e);
            throw new OperationFailedException("Failed to clear failed authentication attempts for user", e);
        }
    }

    @Override
    public int getNumberOfFailedMFAAttempts(String username) throws OperationFailedException {
        String query = "SELECT numberOfMFAAttempts FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("numberOfMFAAttempts");
            } else {
                return 0;
            }
        } catch (SQLException e) {
            logger.error("Failed to retrieve number of failed MFA attempts for user", e);
            throw new OperationFailedException("Failed to retrieve number of failed MFA attempts for user", e);
        }
    }

    @Override
    public void failedMFAAttempt(String username) throws OperationFailedException {
        String query = "SELECT numberOfMFAAttempts FROM users WHERE username = ?";
        int prevAttempts = 1;
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                prevAttempts += resultSet.getInt("numberOfMFAAttempts");
            }
        } catch (SQLException e) {
            logger.error("Failed to retrieve number of failed MFA attempts for user", e);
            throw new OperationFailedException("Failed to retrieve number of failed MFA attempts for user", e);
        }
        query = "UPDATE users SET numberOfMFAAttempts=?, lastMFAAttempt=? WHERE username =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setLong(1, prevAttempts);
            stmt.setLong(2, System.currentTimeMillis());
            stmt.setString(3, username);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to update number of failed MFA attempts for user", e);
            throw new OperationFailedException("Failed to update number of failed MFA attempts for user", e);
        }
    }

    @Override
    public void clearFailedMFAAttempts(String username) throws OperationFailedException {
        String query = "UPDATE users SET numberOfMFAAttempts=? WHERE username =?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setLong(1, 0);
            stmt.setString(2, username);
            stmt.execute();
        } catch (SQLException e) {
            logger.error("Failed to clear number of failed MFA attempts for user", e);
            throw new OperationFailedException("Failed to clear number of failed MFA attempts for user", e);
        }
    }

    @Override
    public long getLastMFAAttempt(String username) throws OperationFailedException {
        String query = "SELECT lastMFAAttempt FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet resultSet = stmt.executeQuery();
            if (resultSet.next()) {
                return resultSet.getLong("lastMFAAttempt");
            } else {
                return 0;
            }
        } catch (SQLException e) {
            logger.error("Failed to retrieve number of failed MFA attempts for user", e);
            throw new OperationFailedException("Failed to retrieve number of failed MFA attempts for user", e);
        }
    }
}
