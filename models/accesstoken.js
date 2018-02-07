const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const accesstokenSchema = new Schema({
    token: {
        type: String
    },
    expirationdate: {
        type: Date
    },
    clientid: {
        type: String,
        index: true
    },
    userid: {
        type: String
    },
    scope: {
        type: String
    }
})

const accesstoken = mongoose.model('accesstoken', accesstokenSchema);
module.exports = accesstoken;