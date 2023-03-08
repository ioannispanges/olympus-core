package eu.olympus.server;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import eu.olympus.model.exceptions.OperationFailedException;
import eu.olympus.server.interfaces.PestoDatabase;
import eu.olympus.server.interfaces.ServerCryptoModule;
import eu.olympus.server.storage.InMemoryKeyDB;
import java.util.HashMap;
import org.junit.BeforeClass;
import org.junit.Test;

public class AuthenticationHandlerTest {

    private static PestoDatabase mockDb;
    private static PestoAuthenticationHandler handler;

    @BeforeClass
    public static void setup(){
        mockDb = mock(PestoDatabase.class);
        handler = new PestoAuthenticationHandler(mockDb,mock(ServerCryptoModule.class), mock(InMemoryKeyDB.class), new HashMap<>());
    }

    @Test(expected = OperationFailedException.class)
    public void deleteAccountDbError() throws OperationFailedException {
        doThrow(OperationFailedException.class).when(mockDb).deleteUser(anyString());
        handler.deleteAccount("username");
    }

    @Test(expected = OperationFailedException.class)
    public void validateMFATokenDbError() throws OperationFailedException {
        doThrow(OperationFailedException.class).when(mockDb).hasUser(anyString());
        handler.validateMFAToken("username","token","type");
    }

    @Test(expected = OperationFailedException.class)
    public void isMFAActivatedDbError() throws OperationFailedException {
        doReturn(true).when(mockDb).hasUser(anyString());
        doThrow(OperationFailedException.class).when(mockDb).getMFAInformation(anyString());
        handler.validateMFAToken("username","token","type");
    }

    @Test(expected = OperationFailedException.class)
    public void conservativeMFAValidationDbError() throws OperationFailedException {
        doThrow(OperationFailedException.class).when(mockDb).hasUser(anyString());
        handler.conservativeMFAValidation("username","token","type");
    }

    @Test(expected = OperationFailedException.class)
    public void activateMFADbError() throws OperationFailedException {
        doThrow(OperationFailedException.class).when(mockDb).hasUser(anyString());
        handler.activateMFA("username","token","type");
    }

    @Test(expected = OperationFailedException.class)
    public void deleteMFADbError() throws OperationFailedException {
        doThrow(OperationFailedException.class).when(mockDb).hasUser(anyString());
        handler.deleteMFA("username","token","type");
    }
}
