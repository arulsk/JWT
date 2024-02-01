const express = require('express');
const app = express();
const port = 4500;
const JWT = require('jsonwebtoken');
const crypto = require('crypto');
const secret_token = crypto.randomBytes(64).toString('hex');

console.log(secret_token);

app.use(express.json());

const generateAccessToken = (userData) => {
  return JWT.sign(userData, secret_token, { expiresIn: '2m' });
};
const generateRefreshToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const refreshTokens = {};

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  JWT.verify(token, secret_token, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

app.post('/login', (req, res) => {
  // Auth
      
  const user_Name = req.body.userName;
  const user_email = req.body.userEmail;
  const user_password = req.body.userPassword;
   
  if(!user_Name || !user_email || !user_password){
      return res.status(500).json({ error : 'specify all parameters'           
      })

  }
     
  const accessToken = generateAccessToken({
    user_Name,
    user_email,
    user_password,
  });

  const refreshToken = generateRefreshToken();
  refreshTokens[refreshToken] = { user_Name, user_email, user_password };

  res.json({ access_token: accessToken, refresh_token: refreshToken });
});

app.post('/refresh', (req, res) => {

  const refreshToken = req.body.refresh_token;
  if (!refreshToken || !refreshTokens[refreshToken]) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }   
  const userData = refreshTokens[refreshToken];
  const accessToken = generateAccessToken(userData);
  res.json({ access_token: accessToken });  
});

app.get('/protected', authenticateToken, (req, res) => {
  const user = req.user;
  res.json({ message: 'This is a protected route', user });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});