
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

server.post('/login', (req, res) => {
    const { username, password } = req.body;

    try {
        const isUser = Users.exists({username: username});
    
        if (!isUser) throw new Error('User not found!');

        Users.findOne({username: username}, (err, user) => {
            const isValid = compare(password, user.password);
            if (!isValid) throw new Error('Wrong Password!');

            const accesstoken = createAccessToken(user._id);
            const refreshtoken = createRefreshToken(user._id);

            Users.updateOne({username: username}, {refreshtoken: refreshtoken}, (err) => {
                if (err)
                    throw new Error(err.message);
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


server.listen(process.env.PORT);


