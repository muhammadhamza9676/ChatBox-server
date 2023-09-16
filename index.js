const express = require('express');
const connectToMongo = require('./db');
var cors = require('cors')
var cookieParser = require('cookie-parser')
const User = require('./models/User');
const Message = require('./models/Message');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
connectToMongo();
const app = express()
const ws = require('ws');
const { connection } = require('mongoose');
const fs = require('fs');

const salt = bcrypt.genSaltSync(10);


const corsOptions = {
  origin: 'http://localhost:3000', // Allow requests from any origin (not recommended for production)
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
};

app.use(express.json());
app.use(cors(corsOptions))
app.use(cookieParser())
app.use('/uploads', express.static(__dirname + '/uploads'))

const port = process.env.PORT || 5000

const jwtsec = process.env.JWT_KEY;

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

async function getUserDataFromReq(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token
    if (token) {
      jwt.verify(token, jwtsec, {}, (err, userData) => {
        if (err) throw err;
        resolve(userData);
      })
    }
    else {
      reject("No Token");
    }
  })
}


app.get('/messages/:userId', async (req, res) => {
  //res.json(req.params);
  const { userId } = req.params;
  const userData = await getUserDataFromReq(req);
  const ourUserId = userData.userId;
  const messages = await Message.find({
    sender: { $in: [userId, ourUserId] },
    recipient: { $in: [userId, ourUserId] },
  }).sort({ createdAt: 1 });
  res.json(messages);
});


app.get('/people', async (req, res) => {
  const users = await User.find({}, { '_id': 1, username: 1 });
  res.json(users);
})



app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const foundUser = await User.findOne({ username });
    if (foundUser) {
      const passOK = bcrypt.compareSync(password, foundUser.password);
      if (passOK) {
        jwt.sign({ userId: foundUser._id, username }, jwtsec, {}, (err, token) => {
          res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
            id: foundUser._id,
          })
        })
      }
    }
  }
  catch (err) {
    if (err) throw err;
    res.status(500).json("Error Logging In");
  }

});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hpass = bcrypt.hashSync(password, salt);
  try {
    const createdUser = await User.create({ username: username, password: hpass });
    jwt.sign({ userId: createdUser._id, username }, jwtsec, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
        id: createdUser._id,
      })
    });
  }
  catch (err) {
    if (err) throw err;
    res.status(500).json("Error Creating User");
  }

});



app.get('/profile', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtsec, {}, (err, userData) => {
      if (err) throw err;
      res.json(userData);
    })
  }
  else {
    res.status(401).json("No Token");
  }

})


app.post('/logout', (req, res) => {
  res.cookie('token', '', { sameSite: 'none', secure: true }).json('Ok');
})

const server = app.listen(4040)
const wss = new ws.WebSocketServer({ server });

wss.on('connection', (connection, req) => {

  function notifyAboutOnlinePeople() {
    [...wss.clients].forEach(client => {
      client.send(JSON.stringify({
        online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username })),
      }));
    });
  }




  connection.isAlive = true;

  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
    }, 1000);
  }, 5000);

  connection.on('pong', () => {
    clearTimeout(connection.deathTimer);
  });




  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies.split(';').find(str => str.startsWith('token='));
    if (tokenCookieString) {
      const token = tokenCookieString.split('=')[1];
      if (token) {
        jwt.verify(token, jwtsec, {}, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }




  connection.on('message', async (message) => {
    messageData = JSON.parse(message.toString());
    const { recipient, text, file } = messageData;
    let filename = null;
    if (file) {
      console.log('size', file.data.length);
      const parts = file.name.split('.');
      const ext = parts[parts.length - 1];
      filename = Date.now() + '.' + ext;
      const path = __dirname + '/uploads/' + filename;
      const bufferData = new Buffer(file.data.split(',')[1], 'base64');
      fs.writeFile(path, bufferData, () => {
        console.log('file saved:' + path);
      });
    }
    if (recipient && (text || file)) {
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient,
        text,
        file: file ? filename : null,
      });
      [...wss.clients].filter(c => c.userId === recipient).forEach(c => c.send(JSON.stringify({ text, sender: connection.userId, recipient, file: file ? filename : null, _id: messageDoc._id })))
    }
  })




  notifyAboutOnlinePeople();


})












