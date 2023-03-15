The *front* module defines a local webserver that will receive standard OIDC requests from a remote server and turn them into the appropriate calls to each of the partial IdPs.

Start the frontend using the command:

>mvn spring-boot:run

The frontend must trust the TLS certificates used by the vIdP, these
are assumed to be stored in 'src/test/resources/truststore.jks' (with the password 'OLYMPUS').

When the frontend is used in connection with the OIDC-Demo-IdP (more information in the corresponding [readme](../oidc-demo-idp/README.md)), the relevant
truststore can be found in oidc-demo-idp/src/test/resources/volatile/truststore.jks
after the TestConfigurationUtil has been used to generate configuration and keys (e.g., after executing '*mvn install*').  
