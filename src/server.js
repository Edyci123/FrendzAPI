
require('dotenv/config')
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { hash, compare } = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { verify } = require('jsonwebtoken');
const { isEmail } = require('validator');
const { sendAccessToken, sendRefreshToken, createAccessToken, createRefreshToken } = require('./tokens.js')
const { isAuth } = require('./isAuth.js');
const { Users } = require('./frendzDB.js')

const server = express();

server.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
server.use(express.json());
server.use(cookieParser());
server.use(express.urlencoded({ extended: true }));

server.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const isUser = await Users.exists({username: username});

        if (isUser) throw new Error('This username already exists!');

        const hashedPassword = await hash(password, 10);
        const newUser = new Users({
            username,
            email,
            password: hashedPassword
        })

        newUser.save();
        
        res.send('User Created!');
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    };

});

server.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const isUser = await Users.exists({username: username});

        let eroare = null;
    
        if (isUser === false) throw new Error('User not found!');

        Users.findOne({username: username}, async (err, user) => {
            const isValid = await compare(password, user.password);

            if (!isValid) return res.send({error: 'Wrong Password'})

            const accesstoken = createAccessToken(user._id);
            const refreshtoken = createRefreshToken(user._id);

            Users.updateOne({username: username}, {refreshtoken: refreshtoken}, (err) => {
                if (err) return res.send({error: `${err.message}`});
            });

            sendRefreshToken(res, refreshtoken);
            sendAccessToken(req, res, accesstoken);
        });
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    };

});

server.post('/getContacts', async (req, res) => {
    try {
        const userID = isAuth(req);
        
        if (userID !== null) {
            res.send({ 
                message: 'Contacts sent'
            });
        } else {
            throw new Error('Something went wrong!');
        }
    } catch (err) {
        res.send({
            error: `${err.message}` 
        });
    };
});

server.post('/logout', (_req, res) => {
    res.clearCookie('refreshtoken', { path: '/refresh_token' })
    res.send({
        message: 'Logged out!'
    });
})

server.post('/refresh_token', (req, res) => {
    const token = req.cookies.refreshtoken;

    if (!token) return res.send({ accesstoken: '' });

    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    };

    const isUser = Users.exists({_id: payload.userID});
    if (!isUser) res.send({ accesstoken: '' });

    const accesstoken = createAccessToken(payload.userID);
    const refreshtoken = createRefreshToken(payload.userID);

    Users.updateOne({_id: payload.userID}, {refreshtoken: refreshtoken}, (err) => {
        if (err) {
            return res.send({ error: `${err.message}` });
        } else {
            sendRefreshToken(res, refreshtoken);
            return res.send({ accesstoken });
        }
    });

});

server.post('/addContacts', (req, res) => {

    try {
        const userID = isAuth(req);
        
        if (userID !== null) {
            const { newContact } = req.body;
            Users.updateOne({_id: userID}, {$push: {contacts: newContact}}, (err) => {
                if (err) console.log(err);
            });
            res.send('User added to your contacts');
        } else {
            throw new Error('Something went wrong!');
        }
    } catch (err) {
        res.send({
            error: `${err.message}`
        });
    }
});


server.listen(process.env.PORT);


