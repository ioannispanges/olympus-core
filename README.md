# License
The source code of the OLYMPUS open source modules is licensed under the Apache License, Version 2.0.

# OLYMPUS code repostory
Welcome to the OLYMPUS source code repository!

OLYMPUS addresses the challenges associated to the use of privacy-preserving identity management solutions by establishing an interoperable European identity management framework based on novel cryptographic approaches applied to currently deployed identity management technologies. In particular, OLYMPUS employs distributed cryptographic techniques to split up the role of the online IDP over multiple authorities, so that no single authority can impersonate or track its users.

# Structure
The project is divided in five sub-projects or modules: [core](core/README.md), [rest-wrapper](rest-wrapper/README.md), [cfp-usecase](cfp-usecase/README.md), [front](front/README.md) and [oidc-demo-idp](oidc-demo-idp/README.md). Two demonstration cases are included in this project: an example deployment of a virtual IdP for a specific use case (for both PESTO and dp-ABC approaches) and a demonstrator of the application of OLYMPUS as an identity provider in an OIDC flow. More information about the OLYMPUS architecture, functionalities and APIs can be found in the [documentation](https://olympus-idp.readthedocs.io/en/latest/).

To build the whole project, use the commands:
>mvn clean
> 
>mvn install

*Note that the 'mvn clean' command is needed to install the MIRACL jar dependency into the local m2 repository in order to build the project.*

*Note that 'mvn install' builds a Docker test setup, so Docker must be running while running this command.*

*DO NOT skip the tests in 'mvn install'. The tests are necessary for constructing tests keys that is compiled into the Docker Images.*

# OIDC demonstrator
To do a test of the system execute:
> cd oidc-demo-idp
> 
> docker compose up

This starts up 3 partial IdPs locally, which together form a virtual IdP.
In another terminal do the following:

> cd front 
> 
> mvn spring-boot:run

This starts a local webserver that will receive standard OIDC requests from a remote server and turn this into the appropriate calls to each of the partial IdPs.
In yet another terminal check out [the olympus service provider project]( https://bitbucket.alexandra.dk/projects/OL/repos/olympus-service-provider) and from its root run:

> npm install
> 
> npm start

This starts the web-facing service provider for Olympus, which relays queries to your local webserver, which is needed since OIDC must relay a query to a *single* destination, which in this case is the local webserver.
To access this open localhost:3000 in a webbrowser. 

Now Olympus is running with an empty in-memory database. The webservice currently only supports log-in, so you must create a user through the test. Specifically use 'oidc-demo-idp.TestFlow.testPestoRunning()' (directory oidc-demo-idp/src/test/java/eu/olympus/oidc/TestFlow.java) to create a user "test" with password "pw1".

# Example vIdP (cfp-usecase) demonstrator
To launch a test vIdP comprised of three partial IdPs run:

>cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup0.json 
>
>cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup1.json 
>
>cfp-usecase> java -jar target/CFP-IdP-jar-with-dependencies.jar src/test/resources/setup2.json

This will start demonstrators using ports 9080-9082(plain HTTP) and 9090-9092(TLS). Using the tests 'cfp-usecase.TestFlow.testPabcRunning()' and 'cfp-usecase.TestFlow.testPabcRunning()', you can execute a simple flow (taking the user role and also verifying the results).


# Acknowledgements
The research leading to these results has received funding from the European Union’s Horizon 2020 Research and Innovation Programme, under Grant Agreement No. 786725 ([OLYMPUS](https://olympus-project.eu))
