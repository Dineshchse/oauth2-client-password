const passport = require('passport')
const BasicStrategy = require('passport-http').BasicStrategy
const ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy
const BearerStrategy = require('passport-http-bearer').Strategy
const crypto = require('crypto')
const Client = require("../models/client")
const AccessToken = require("../models/accesstoken");
const User = require("../models/user")
const redis = require('redis');
const redisPort = process.env.redisPort;
const rclient = redis.createClient(redisPort);

rclient.on("error", function (err) {
    console.log("Error " + err);
});

/**
 * These strategies are used to authenticate registered OAuth clients.
 * The authentication data may be delivered using the basic authentication scheme (recommended)
 * or the client strategy, which means that the authentication data is in the body of the request.
 */
passport.use("clientBasic", new BasicStrategy(
    function (clientId, clientSecret, done) {
        Client.findOne({clientid: clientId}, function (err, client) {
            if (err) return done(err)
            if (!client) return done(null, false)
            if (!client.trustedclient) return done(null, false)

            if (client.clientsecret == clientSecret) return done(null, client)
            else return done(null, false)
        });
    }
));

passport.use("clientPassword", new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        Client.findOne({clientid: clientId}, function (err, client) {
            if (err) return done(err)
            if (!client) return done(null, false)
            if (!client.trustedclient) return done(null, false)

            if (client.clientsecret == clientSecret) return done(null, client)
            else return done(null, false)
        });
    }
));

/**
 * This strategy is used to authenticate users based on an access token (aka a
 * bearer token).
 */
passport.use("accessToken", new BearerStrategy(
    function (accessToken, done) {
        console.log(accessToken);
        const accessTokenHash = crypto.createHash('sha256').update(accessToken).digest('hex')

        // First Check in redis cache
        rclient.hgetall(accessTokenHash, function (err, obj) {            
            console.log(obj);
            if (obj == null){ 
                console.log("Offo! Object is null in Redis");

                // Entry not found in redis cache
                // Need to go to DB to find
                AccessToken.findOne({token: accessTokenHash}, function (err, token) {
                    if (err) return done(err)
                    if (!token) return done(null, false)
                    if (new Date() > token.expirationdate) {
                        done(null, false)
                    } else {
                        User.findOne({username: token.userid}, function (err, user) {
                            if (err) return done(err)
                            if (!user) return done(null, false)
                            // no use of scopes for no
                            var info = { scope: '*' }
                            done(null, user, info);
                        })
                    }
                })                
            }
            // Entry found in redis cache
            // Check the expiration of the entry
            else if (new Date().getTime() > Number(obj.expirationdate)) {
                console.log("Offo! time expired");
                done(null, false)
            } else {
                // no use of scopes for no
                var info = { scope: '*' }
                done(null, obj.userid, info);
            }
        });        
    }    
))
