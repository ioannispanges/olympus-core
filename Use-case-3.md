# Use case 3
This document describes the steps of use case 3 and how to perform them.

## Flow
The flow of this use case is as follows.
The user wish to create on online reservation at the Service Provider. To do this, the user chose to authenticate with Olympus.
User registers at Olympus, entering name, email, and date of birth. User logs in, and is returned to the Service Provider.
The Service Provider receives the information that is needed, and the user is either allowed to make a reservation, or not.

## Deployment
To build the modules necessary, enter the root directory of the project and use the command
>mvn install

*Note that the modules depend on the core module.
*Note that 'mvn install' builds a Docker test setup, so Docker must be running while running this command.*
*DO NOT skip the tests in 'mvn install'. The tests are necessary for constructing tests keys that is compiled into the Docker Images.*

Afterward, there are three parts to deploying the necessary services.

### OLYMPUS vIdP
To deploy the OLYMPUS vIPD enter the folder /oidc-demo-idp and start the vIDP with the command:
> docker compose up

### OLYMPUS Front
To deploy the OLYMPUS Front enter the folder /front and start it with the command:
> mvn spring-boot:run

### Service Provider
To deploy the Service Provider, first clone the project from https://bitbucket.alexandra.dk/projects/OL/repos/olympus-service-provider.
Enter the root of the project folder and start the Service Provider using the command:
>npm run start

## Step by step
This section describes which steps to take to complete the flow of the use case, after all services has been deployed.

* The Service Provider is located at http://localhost:3000.
* Choose to log in.
* Choose 'Connect with Olympus'
* Choose 'Sign up'
* Enter name, birthdate, email, username and password.
* Click the 'Sign up'-button. Upon success, you are returned to the login screen
* Enter username and password. Click 'Log in'
* The Service Provider should now inform you of the username you chose.
  If you are old enough to book a table, the service provider will tell you that you are successful in making your booking.
  If you are not old enough, you are returned to the original log in screen.
