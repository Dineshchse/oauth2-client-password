const express = require('express');
const passport = require('passport');
const bodyParser = require('body-parser');
const mongo = require("./db/index");
const registration = require("./routes/registration");
const auth = require("./oauth/auth");
const oauth = require("./oauth/oauth");

const app = express();
app.use(bodyParser.urlencoded({extended : true}));
app.use(bodyParser.json());
app.get("/greet", (req, res)=>{
    res.send("Hi !!!!!!!!!!!!");
})
app.post("/register", registration.registerUser)
app.post("/oauth/token", oauth.token);
app.get('/restricted', passport.authenticate('accessToken', { session: false }), function (req, res) {
    res.send("Yay, you successfully accessed the restricted resource!")
})
app.get('/logout', passport.authenticate('accessToken', { session: false }), function (req, res) {    
    registration.revokeAccessToken(req, res);
})

app.listen(1223, () =>{
    console.log("Running on port 1223");
})