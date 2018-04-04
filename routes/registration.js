const bcrypt = require("bcrypt");
const crypto = require('crypto')
const User = require("../models/user");
const redis = require('redis');
const AccessToken = require("../models/accesstoken");
const RefreshToken = require("../models/refreshtoken");

const redisPort = process.env.redisPort;
const rclient = redis.createClient(redisPort);

rclient.on("error", function (err) {
    console.log("Error " + err);
});

const saltRounds = 11;

module.exports = {
    registerUser(req, res, next){
        const {username, password} = req.body;
        User.find({username})
            .then((users) => {
                if(users.length !==0) {
                    res.status(422).send({error: "username is already taken"})
                } else {
                    return bcrypt.hash(password, saltRounds)
                }
            })
            .then(hash =>{
                User.create({username, password:hash})
            })
            .then(() =>{
                res.status(201).send({username})
            })
            .catch(next)
    }
}


revokeAccessToken =
    function(req, res){
        const authorization = req.headers.authorization;
        if(authorization != null && authorization.includes("Bearer")){
            const accessToken = authorization.substring("Bearer".length + 1);

            console.log(accessToken);
            const accessTokenHash = crypto.createHash('sha256').update(accessToken).digest('hex');
            
            // First delete from redis cache
            rclient.del(accessTokenHash);

            // Delete from DB
            AccessToken.findOneAndRemove({'token' : accessTokenHash}, function(err, token){
                if(err) res.send("Error in logging out");
                res.send("You successfully logged out");        
            })                        
        }
    }

module.exports.revokeAccessToken = revokeAccessToken