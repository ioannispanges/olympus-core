The main part of Olympus can be found in this (*core*) module, which contains code implementing both a client, server (partial IdP) and verifier (Relying Party). Note that the core codebase includes some client and IdP code primarily intended for comparison/benchmarking (the password jwt and distributed rsa components).

To build this module, use the commands:
>mvn clean
> 
>mvn install

*Note that the 'mvn clean' command is needed to install the MIRACL jar dependency into the local m2 repository in order to build the project.*
