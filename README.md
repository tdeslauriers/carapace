# carapace

**Intended Use:**

1. Reusable, core functionality for building microservices.
1. Cli called `exo`, as in exoskeleton, for microservice-support activities like certificate generation.

**Definition:** _a bony or chitinous case or shield covering the back or part of the back of an animal (such as a turtle or crab)._

**Description:** A learning project to build the components of a microservice that are often handled 'under the hood' in Java web frameworks such as Spring Cloud or Micronaut.

1. Like those projects, the intent is to make reusable packages for other projects to consume and utilize.
2. As the name suggests, there is a slant toward security and overall service hardening, ie, an exoskeleton that can house and provide functionality to microservices so design can focus on service logic.

**Language Choice**: I chose `Go` because it is like the 'Sport Mode' version of an automatic transmission. You get a lot of the same control you get with a stick shift, with out the difficulty of but the standard library is really robust so the development ba

- The secondary challenge of the learning project is to use as few 3rd party libraries as possible and over time get rid of all of them.

## Library Components (thus far):

1. Health endpoint
1. mTLS Server
1. mTLS Client
1. Get, Post, Put s2s HTTP request/response handling
   - including common error handling
1. SQL connection
   - Maria DB
1. Certificate Generation
   - ECDSA
     - CAs
     - Leaf
1. Field level encryption for sensitive service data using AES GCM 256
1. Blind index creation for database indexing encrypted data
   - HMAC
1. Service to Service login credential validation
1. Jwt Mint:
   - signs
   - verifies
1. Service to Service http call templates
   - Adds service and user tokens if exists
   - deserializes json response or error
1. `exo cli` flag definitions and execution functions
