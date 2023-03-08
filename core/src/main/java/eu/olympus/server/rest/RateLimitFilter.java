package eu.olympus.server.rest;

import com.revinate.guava.util.concurrent.RateLimiter;
import eu.olympus.server.interfaces.PestoBasedIdP;
import javax.annotation.Priority;
import javax.servlet.ServletContext;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Secured
@Provider
@Priority(Priorities.AUTHENTICATION)
public class RateLimitFilter implements ContainerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);
    private RateLimiter rateLimiter;
    private static final String AUTHENTICATION_SCHEME = "Bearer";
    @Context
    ServletContext context;

    private RateLimiter getRateLimiter(){
        if(rateLimiter == null){
            PestoBasedIdP idp = (PestoBasedIdP) context.getAttribute("idp");
            rateLimiter = RateLimiter.create(idp.getRateLimit());
        }
        return rateLimiter;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
            if(!getRateLimiter().tryAcquire(1)){
                logger.warn("Rate limited reached, dropping "+requestContext.getUriInfo().getPath());
                requestContext.abortWith(
                    Response.status(Response.Status.NOT_ACCEPTABLE)
                        .header(HttpHeaders.WWW_AUTHENTICATE,
                            AUTHENTICATION_SCHEME)
                        .build());
            }
    }
}
