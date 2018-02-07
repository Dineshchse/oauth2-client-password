const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: {
        type: String,
        index: true
    },
    password: {
        type: String
    }
})

const user = mongoose.model('user', userSchema);
module.exports = user;