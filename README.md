# OAuth Study

## Summary
This project is just to gain practice with Go and to learn the ins and outs of OAuth 2.0 and OpenID Connect.

> WARNING: This project is not production ready code.  It is meant as a vehicle for learning and has not
> undergone the extensive testing required for a piece of security software that can be relied upon.

TLS is a requirement for OAuth, but is left out of this service as many environments utilize TLS termination
at some internal boundary. (also, see above warning)

The only grant type currently supported is "code".  "password" and "client_credentials" grant types may be
supported in the future.

The implicit authorization flow is not supported as RFC 8252 mentions problems with it for native apps.

Currently, Authorization Codes are an encrypted self-describing struct.  This leads to codes being rather
long and I don't know if I like this. (maybe it's just the URL encoding)  I use self-describing structs to
ensure that if multiple copies of this service are running side-by-side, they can remain as stateless as
possible.

File repositories are currently used for development as they are easier than spinning up a DB.  However, I
have not written any unit tests for them, so they drag the coverage numbers down a bit.

There are two directories that are referenced by configuration but are in .gitignore: "filerepos" and
"cryptokeys".  The contents of these directories are something that should never be checked into version
control.  For the repos, tests have their own mechanisms for test data, and the possibility of production
data being in a code repo is not good.  Any cryptographic key belongs in two places and only two places:
A machine that is running the service, and a secrets server.

If you want to run this service, you'll need to generate a 32 byte AES key and add it to the cryptokeys
directory.  Double check that config/config.json has the correct file name.

Users and Clients can be registered at run time.

## 3rd party packages
Using Gorilla mux instead of Go's http mux.

Using Uber's Zap library for structured logging.  Logging plain strings is not a sustainable strategy when
you have several service instances, and/or a request can traverse more than one service's logs.

Using bcrypt for User passwords and Client secrets.

Using github.com/micro/go-config for configuration.  Not really necessary as I don't intend to do a lot of
config shenanigans in this project, but I plan on looking at the micro framework in more depth later.

## Backlog

### Backing types
These are just featured enough to support the OAuth flow.

Users
- [x] Registration
- [ ] Password strength requirements

Clients
- [x] Registration
- [x] Secret regeneration

### OAuth functionality

#### Authorization endpoint
- [x] Endpoint works
- [x] Resource Owner HTTP Basic authentication
- [ ] Resource Owner OpenID Connect authentication
- [x] Generates a self descriptive object that is encrypted and sent
- [ ] Add a web page for Resource Owner to actively consent to Client authorization
- [ ] Add a system to handle more than one scope
- [ ] Sign Authorization Codes
- [ ] PKCE protection (RFC 7636)

#### Token endpoint
- [ ] Endpoint works
- [ ] Require Client authentication for non-public Clients
- [ ] Token revocation on Client secret regeneration
- [ ] Issue refresh tokens

### OpenID Connect
- [ ] TODO

### HTTP Middleware
- [x] Request ID is added to the request's context
- [x] Logger is added to the request's context
    - [x] Request ID is added to the logger
- [x] Basic request logging: start, stop, duration, response code
- [x] Panic handler
- [x] Body extraction handler to read message bodies in a safe and consistent way (i.e. don't read/accept more than x bytes)
    - See handler comments for why this must break the http.Handler abstraction.
    - [ ] Make body size limit configurable

### Other
- [ ] Add Postman collection for live testing
- [ ] Support more than one configured decrypter to allow for rolling updates when keys are rotated
- [ ] Move file repositories into their own package to get accurate coverage numbers

## Unit Tests
Most features have a solid body of unit tests.  My basic philosophy is that every semantic of an API
should have its own unit test.  Using the Arrange, Act, Assert model of unit testing, this leads to a
fair amount of copy/paste of groups of tests, with only the asserts being different.

As an example, take the following definition:
``` Go
func (tokenSvc *AuthTokenService) CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID uuid.UUID) (code []byte, err error)
```

The using basic happy path arguments, this one call yields the following semantics just by the method signature:

- The code was returned
- err is nil
- userID was used to retrieve the User
- clientID was used to retrieve the Client

The following semantics are due to the knowedge of what an authorization code looks like in this system

- The code can be decrypted and deserialized to the self-descriptive token using the configured crypto
- The code is well formed
    - User ID properly set
    - Client ID properly set
    - appropriate "Issued At"
    - "Expires" == "Issued At" + configured TTL

Each of those blocks of semantics could be a block of asserts in a single method.  But by elevating them to
full test cases, you signal to other developers that they are important and any modification to them is a
potentialy breaking change.  It also helps keep fat fingers from deleting them. (code review doesn't catch
everything)
