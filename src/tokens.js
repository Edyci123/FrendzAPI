const { sign } = require('jsonwebtoken')

const createAccessToken = userID => {
    return sign({userID}, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '15m'
    });
};

const createRefreshToken = userID => {
    return sign({userID}, process.env.REFRESH_TOKEN_SECRET,  {
        expiresIn: '15m'
    });
};

const sendAccessToken = (req, res, accesstoken) => {
    res.send({
        accesstoken,
        username: req.body.username
    });
};

const sendRefreshToken = (res, refreshtoken) => {
    res.cookie('refreshtoken', refreshtoken, {
        httpOnly: true,
        path: '/refresh_token'
    });
};

module.exports = {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken
};