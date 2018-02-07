const oauth2orize = require('oauth2orize')
const passport = require("passport")
const crypto = require("crypto");
const bcrypt = require("bcrypt")
const utils = require("../utils");
const User = require("../models/user");
const AccessToken = require("../models/accesstoken");
const RefreshToken = require("../models/refreshtoken");

const server = oauth2orize.createServer();

server.exchange(oauth2orize.exchange.password((client, username, password, scope, done)=>{
    //check for client
    User.findOne({username}, function(err, user){
        if (err) return done(err)
        if (!user) return done(null, false)
        bcrypt.compare(password, user.password, function (err, res) {
            if(!res) return done(null, false);
            const token = utils.uid(256)
            const refreshToken = utils.uid(256)
            const tokenHash = crypto.createHash('sha1').update(token).digest('hex')
            const refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex')
            
            const expirationDate = new Date(new Date().getTime() + (3600 * 1000))// move this to some config file

            AccessToken.findOneAndUpdate({userid:username}, 
                {$set: {token: tokenHash, expirationdate:expirationDate, clientid: client.clientid, userid: username, scope:scope }},
                {upsert:true},
                function(err){
                    if(err) return done(err)
                    RefreshToken.findOneAndUpdate({userid: username}, 
                        {$set:{refreshtoken: refreshTokenHash, clientid: client.clientid, userid: username }}, 
                        {upsert:true},
                        function(err){
                        if(err) return done(err)
                        done(null, token, refreshToken, {expires_in: expirationDate})
                    })
                })

        })
    })
        
}))

//Refresh Token
server.exchange(oauth2orize.exchange.refreshToken((client, refreshToken, scope, done) =>{
    const refreshTokenHash = crypto.createHash('sha1').update(refreshToken).digest('hex')

    RefreshToken.findOne({refreshtoken: refreshTokenHash}, function (err, token) {
        if (err) return done(err)
        if (!token) return done(null, false)
        if (client.clientid !== token.clientid) return done(null, false)
        
        const newAccessToken = utils.uid(256)
        const accessTokenHash = crypto.createHash('sha1').update(newAccessToken).digest('hex')
        
        const expirationDate = new Date(new Date().getTime() + (3600 * 1000))
    
        AccessToken.findOneAndUpdate({userid: token.userId}, {$set: {token: accessTokenHash, scope: scope, expirationdate: expirationDate}}, function (err) {
            if (err) return done(err)
            done(null, newAccessToken, refreshToken, {expires_in: expirationDate});
        })
    })
}))

// token endpoint
exports.token = [
    passport.authenticate(['clientBasic', 'clientPassword'], { session: false }),
    server.token(),
    server.errorHandler()
]