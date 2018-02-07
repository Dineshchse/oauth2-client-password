const bcrypt = require("bcrypt");
const User = require("../models/user");

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