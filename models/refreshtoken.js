const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const refreshtokenSchema = new Schema({
    refreshtoken: {
        type: String
    },    
    clientid: {
        type: String,
        index: true
    },
    userid: {
        type: String
    }
})

const refreshtoken = mongoose.model('refreshtoken', refreshtokenSchema);
module.exports = refreshtoken;