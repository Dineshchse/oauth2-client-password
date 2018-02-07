# oauth2-client-password
Oauth2 implementation using passportjs+ node+ express+ mongo

Use the mongodump oauth.gz file in the backup folder to restore the collections i.e. users, clients, refreshtokens, accesstokens.

Once restored into mongoDB, Use Postman to verify the APIs

Details:
POST Method
Host: localhost:1223
Route: /oauth/token

Go to Authorization tab
Select "Basic Auth" from dropdown
set clientid and clientsecret - 
user: test
password : pass123

Go to Headers tab
Content-Type: application/json
Payload:
{
    "username":"dinesh",
    "password":"optym123",
    "grant_type": "password"
}

The above API returns an access_token, use this token to call your API which you have secured.
GET http://localhost:1223/restricted
Go to Authorization tab
Select "Bearer Token" from dropdown and paste the copied token in the Token field.
