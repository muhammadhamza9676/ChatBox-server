const express = require('express');
const connectToMongo = require('./db');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const User = require('./models/User');
const Message = require('./models/Message');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const ws = require('ws');
const fs = require('fs');

connectToMongo();

const app = express();
const salt = bcrypt.genSaltSync(10);
const jwtsec = process.env.JWT_KEY;
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_URL, methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', credentials: true }));
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

// Helper function to get user data from the request
async function getUserDataFromReq(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtsec, {}, (err, userData) => {
        if (err) {
          reject("Invalid token");
        } else {
          resolve(userData);
        }
      });
    } else {
      reject("No token");
    }
  });
}

// Login endpoint with error handling
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const foundUser = await User.findOne({ username });

    if (!foundUser) {
      return res.status(401).json("User not found");
    }

    const passOK = bcrypt.compareSync(password, foundUser.password);
    if (!passOK) {
      return res.status(401).json("Incorrect password");
    }

    jwt.sign({ userId: foundUser._id, username }, jwtsec, {}, (err, token) => {
      if (err) {
        return res.status(500).json("Error signing JWT");
      }
      res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
        id: foundUser._id,
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json("Server error");
  }
});


// Registration endpoint with error handling
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if username is at least 3 characters long
  if (username.length < 3) {
    return res.status(400).json("Username must be at least 3 characters long");
  }

  // Check if password is at least 5 characters long
  if (password.length < 5) {
    return res.status(400).json("Password must be at least 5 characters long");
  }

  try {
    // Check if a user with the same username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json("User already registered");
    }

    const hashedPassword = bcrypt.hashSync(password, salt);
    const createdUser = await User.create({ username, password: hashedPassword });

    jwt.sign({ userId: createdUser._id, username }, jwtsec, {}, (err, token) => {
      if (err) {
        return res.status(500).json("Error signing JWT");
      }
      res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
        id: createdUser._id,
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json("Error creating user");
  }
});


// Profile endpoint with error handling
app.get('/profile', async (req, res) => {
  try {
    const userData = await getUserDataFromReq(req);

    if (!userData) {
      // If no user data is found, send a response indicating that no user is logged in.
      res.status(401).json("No user is logged in");
    } else {
      // If user data is found, send the user data as a JSON response.
      res.json(userData);
    }
  } catch (err) {
    // console.error(err);
    // res.status(500).json("Server error");
  }
});



// Logout endpoint
app.post('/logout', (req, res) => {
  res.cookie('token', '', { sameSite: 'none', secure: true }).json('OK');
});

// Messages endpoint with error handling
app.get('/messages/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const userData = await getUserDataFromReq(req);
    const ourUserId = userData.userId;
    const messages = await Message.find({
      sender: { $in: [userId, ourUserId] },
      recipient: { $in: [userId, ourUserId] },
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (err) {
    console.error(err);
    res.status(500).json("Server error");
  }
});

// People endpoint with error handling
app.get('/people', async (req, res) => {
  try {
    const users = await User.find({}, { '_id': 1, username: 1 });
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json("Server error");
  }
});

const server = app.listen(process.env.WSS_PORT);
const wss = new ws.WebSocketServer({ server });


const userStatusMap = {};




// WebSocket server logic
wss.on('connection', (connection, req) => {

  function notifyAboutOnlinePeople() {
    [...wss.clients].forEach(client => {
      client.send(JSON.stringify({
        online: [...wss.clients].map(c => ({ userId: c.userId, username: c.username })),
      }));
    });
  }


  function notifyOnlineStatus(userId, status) {
    [...wss.clients].forEach(client => {
      client.send(JSON.stringify({
        userStatusUpdate: { userId, status },
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

    if (messageData.userStatusUpdate) {
      const { userId, status } = messageData.userStatusUpdate;

      // Update the user status in the map
      userStatusMap[userId] = status;

      // Notify all clients about the status change
      notifyOnlineStatus(userId, status);
    }
    else{
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
  }
  
  })


  




  notifyAboutOnlinePeople();


})












