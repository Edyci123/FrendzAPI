
const mongoose = require('mongoose');
const {compare}

mongoose.connect('mongodb://localhost:27017/frendzDB');

const userSchema = new mongoose.Schema({
    username: String, 
    email: String,
    password: String,
    refreshtoken: String,
    contacts: Array
});

const Users = new mongoose.Users('Users', userSchema);

module.exports = {
    Users
};


