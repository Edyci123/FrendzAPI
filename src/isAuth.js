const { verify } = require('jsonwebtoken');

const isAuth = req => {
    const authorization = req.headers['authorization'];
    if (!authorization) throw new Error('You need to login');

    const token = authorization.split(' ')[1];
    const { userID } = verify(token, process.env.ACCESS_TOKEN_SECRET);
    return userID;
}

module.exports = {
    isAuth
};