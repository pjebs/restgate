This is an example of using RestGate with JWT
===============


1) Run the example API server
 ```shell
   go run example-jwt.go
```
2) Run curl to login and get a new token from the /api/login endpoint that is protected via username/password
```shell
curl -X GET \
  http://localhost:8080/api/login \
  -H 'X-Auth-Key: user1' \
  -H 'X-Auth-Secret: password1'
  -D headers.txt
```
3) curl will store all the headers from the API on the file: `headers.txt`

4) Get the value of the `Authorization` header from the headers.txt file
5) Run curl and paste the value of the header
```shell
curl -X GET \
  http://localhost:8080/api/get \
  -H 'Authorization: <paste_header_value>'
```
6) You'll get a valid response from the API:

```
/api/get -> apiGetHandler - protected by RestGate (JWT mode)
Welcome back user1!

Token Information:
Issued By: restgate-jwt-example
On: <DATE>
Expires: <DATE>
```
