const mongoose = require("mongoose");
const config = require("./config");

mongoose.Promise = global.Promise;
// connect to mongoDB 
mongoose.connect(config.connection);

mongoose.connection
    .once("open", () =>{ console.log("mongoDB is connected")})
    .on("error", err =>{
        console.warn("Warning", err);
    })

