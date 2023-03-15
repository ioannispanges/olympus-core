The *oidc-demo-idp* module uses the Olympus-core to generate a vIdP (formed by 3 IdPs) to show an application as the identity provider in a OIDC. To fully realize the example, the frontend for the standard OIDC requests is needed (check corresponding [readme](../front/README.md)).

To build the module, use the command:
>mvn install

*Note that this module depends on the core module, so this may trigger (if the core module has not been built previously, or has been changed) the build of that module (more information in the corresponding [readme](../core/README.md)).
*Note that 'mvn install' builds a Docker test setup, so Docker must be running while running this command.*
*DO NOT skip the tests in 'mvn install'. The tests are necessary for constructing tests keys that is compiled into the Docker Images.*

To start the IdP:
> docker compose up

