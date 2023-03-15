The *cfp-usecase* is a wrapper that shows how the Olympus-core is applied to a specific use-case. To build the module, use the command in the cfp-usecase directory:

>mvn install

*Note that this module depends on the core module, so this may trigger (if the core module has not been built previously, or has been changed) the build of that module (more information in the corresponding [readme](../core/README.md)).


A sample vIdP can be run from this sub-project using the command:

>java -jar CFP-IdP-jar-with-dependencies.jar

ie. to use the sample vIdP setup, open 3 terminals and start the 3 partial IdPs:

>cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup0.json 
>
>cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup1.json 
>
>cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup2.json

This will start demonstrators using ports 9080-9082(plain HTTP) and 9090-9092(TLS). Using the tests 'cfp-usecase.TestFlow.testPabcRunning()' (for the p-ABC approach) and 'cfp-usecase.TestFlow.testPestoRunning()' (for the PESTO approach), you can can execute a simple example flow that creates (and after testing deletes) a user, adds attribute values, and does a presentation adhering to a policy that includes attribute revelation, hiding and range predicates. 

In order to initiate the intra-server key refresh protocol, an administrator may make a HTTP POST request to /idp/startRefresh on one of the partial IdPs. This can be done using any HTTP client, eg. curl: 'curl -s -X POST -H "Authorization: Bearer " '

In order to start the refresh protocol using the setup in the cfp-usecase project, the following command would be used: 'curl.exe -s -X POST -H "Authorization: Bearer eimLN2/sr73deAVV8D/3FXFUNbSRdu3d/FJtWLCXGhu9+i6fiHcS54MyIOG6MczVR7r941CI+H1dbgDIVi+xHQ==" http://localhost:9080/idp/startRefresh'
