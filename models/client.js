const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const clientSchema = new Schema({
    clientid: {
        type: String,
        index: true
    },
    clientsecret: {
        type: String
    },
    trustedclient: {
        type: Boolean
    }
})

const client = mongoose.model('client', clientSchema);
module.exports = client;