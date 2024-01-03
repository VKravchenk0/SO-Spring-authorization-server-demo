## Spring Authorization Server example: Authorization server and Resource server combined in a single application.
### Sample project to demonstrate the answer for the [stackoverflow question](https://stackoverflow.com/questions/70949390/spring-authorization-and-resource-on-same-server/70958977).   
The code in the README uses the [HTTPie CLI](https://github.com/httpie/cli).  
Swagger UI is available on http://localhost:8080/swagger-ui/index.html

This application has two sets of test endpoints:
1. `/test/**` - endpoints protected with the session cookie. Will be accessible after completing the default Spring Security login (`/login` endpoint)
2. `/api/test/**` - endpoints protected with the JWT token. Will be accessible after obtaining the access token with the OAuth2 flow.

## Authorization code flow with PKCE demo:

### 1. Start the app:
```
./mvnw spring-boot:run
```

### 2. Making sure `**/protected` endpoints are inaccessible for now (returning 401 or redirect to login)
```
http localhost:8080/test/protected
http localhost:8080/api/test/protected
```


### 3. OIDC login
#### 3.1. Calling the Spring Security `/login` endpoint. In case of success, we expect 302 redirect to the root path (default Spring Security behavior). The session cookie will be stored in the `testsession`
```
http --session=testsession --form POST localhost:8080/login \
    username=user@example.com \
    password=password
```
#### 3.2. Checking that `/test/protected` is now accessible:
```
http --session=testsession localhost:8080/test/protected
```
#### 3.2. Making sure `/api/test/protected` is still inaccessible:
```
http --session=testsession localhost:8080/api/test/protected
```
#### 3.3. Introspecting the Spring Security session-based authentication object (expecting `UsernamePasswordAuthenticationToken`):
```
http --session=testsession localhost:8080/test/currentUser
```

### 4. OAuth2 Authorization Code Flow with PKCE. 
#### 4.1 Initializing the PKCE variables (NOTE: do not hardcode them in real projects):
```
CODE_VERIFIER=KImxEAikOHgWrAGTgbF3YXnAZ3RBy_1Oijcenvpi3Z_oL2Kfk0vxIhKhmxSZW4IHQhTyB7Rh1_07E1u6RJFw_2G41f9NyP4mMR4BRAhRgBKRDuYbXIIYTwkfoZs_YfDL
CODE_CHALLENGE_METHOD=S256
CODE_CHALLENGE=tpv22FEqJbXNrge_mtAYpNP2gTTm7WF8cPrVI8gpNBY
```

#### 4.2 Obtaining the authorization code: calling the `/oauth2/authorize` endpoint and extracting the code from the response location header
```
AUTHORIZATION_CODE=$(
  http --session=testsession -v GET localhost:8080/oauth2/authorize \
    response_type==code \
    client_id==oidc-client \
    code_challenge==$CODE_CHALLENGE \
    code_challenge_method==$CODE_CHALLENGE_METHOD |
  grep -i '^location:' |
  awk -F'code=' '{print $2}' |
  tr -d '\r'
) && printf "\nAuthorization code: $AUTHORIZATION_CODE \n" || printf "\nFailed to extract authorization code from the response.\n"
```

#### 4.3. Using the authorization code to obtain the access token (`/oauth2/token`):
```
ACCESS_TOKEN=$(
  http --form POST localhost:8080/oauth2/token \
    code=$AUTHORIZATION_CODE \
    grant_type=authorization_code \
    client_id=oidc-client \
    code_verifier=$CODE_VERIFIER | 
  jq -r '.access_token'
) && printf "\nAccess token: $ACCESS_TOKEN \n" || printf "\nFailed to get the access token.\n"
```

### 5. Verification:
#### 5.1. Checking that `/api/test/protected` is now accessible with the JWT access token:
```
http GET localhost:8080/api/test/protected Authorization:"Bearer $ACCESS_TOKEN"
```
#### 5.2. Introspecting the Spring Security bearer token authentication object (expecting `JwtAuthenticationToken`):
```
http GET localhost:8080/api/test/currentUser Authorization:"Bearer $ACCESS_TOKEN"
```