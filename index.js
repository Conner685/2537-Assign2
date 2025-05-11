require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const salt = 12;
const connectToDatabase = require('./databaseConnections');

let userCollection;

(async () => {
    const db = await connectToDatabase();
    userCollection = db.collection('users'); 
})();

const {
  SESSION_CODE: secretSession,
  MONGO_SECRET: dbSecret,
  MONGO_USER: dbUser,
  MONGO_PASSWORD: dbPassword,
  MONGO_HOST: dbHost,
  MONGODB_DATABASE: dbName,
  PORT = 3000
} = process.env;

if (!secretSession) {
  throw new Error('SESSION_CODE is not defined in environment variables');
}

const app = express();
const expireTime = 1000 * 60 * 60;

async function connectDB() {
  const uri = `mongodb+srv://${dbUser}:${dbPassword}@${dbHost}/${dbName}?retryWrites=true&w=majority`;
  const client = new MongoClient(uri);
  try {
    await client.connect();
    return client.db(dbName);
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
}

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${dbUser}:${dbPassword}@${dbHost}/sessions`,
  crypto: { secret: dbSecret },
  collectionName: 'sessions'
});


app.use(express.urlencoded({ extended: false }));

app.use(express.static('public'));

app.use(session({
  secret: secretSession,
  store: mongoStore,
  saveUninitialized: false,
  resave: true,
  cookie: { maxAge: expireTime, httpOnly: true }
}));

app.get('/', (req, res) => {
  if (req.session.authenticated) {
    res.send(`
      <h1>Hello ${req.session.name}!</h1>
      <a href="/members">Members Area</a><br>
      <a href="/logout">Logout</a>
    `);
  } else {
    res.send(`
      <h1>Hello User!</h1>
      <a href="/login">Login</a><br>
      <a href="/createUser">Sign Up</a>
    `);
  }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/createUser', (req,res) => {
  var html = `
  <h1>Create User</h1>
  <form action='/submitUser' method='post'>
      <input name='name' type='text' placeholder='Your Name' required><br>
      <input name='email' type='email' placeholder='Email' required><br>
      <input name='password' type='password' placeholder='Password' required><br>
      <button>Submit</button>
  </form>
  <a href="/">Back to Home</a>`;
  res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='email' placeholder='Email' required>
    <input name='password' type='password' placeholder='Password' required>
    <button>Submit</button>
    <a href='/'>Back to Home</a>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
      name: Joi.string().max(50).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required()
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
      const errorMessage = validationResult.error.details[0].message;
      res.send(`
          <h1>Error: ${errorMessage}</h1>
          <a href="/createUser">Try again</a>`
        );
      return;
  }

  const existingUser = await userCollection.findOne({ email });
  if (existingUser) {
      res.send(`
          <h1>Error: Email already registered</h1>
          <a href="/createUser">Try again</a>`
        );
      return;
  }

  try {
      const hashedPassword = await bcrypt.hash(password, salt);
      await userCollection.insertOne({
          name,
          email,
          password: hashedPassword
      });

      req.session.authenticated = true;
      req.session.email = email; 
      req.session.name = name; 
      req.session.cookie.maxAge = expireTime;
      
      res.redirect('/');
  } catch (error) {
      console.error('Error creating user:', error);
      res.send(`
          <h1>Error creating account</h1>
          <a href="/createUser">Try again</a>
      `);
  }
});

app.post('/loggingin', async (req, res) => {
  const email = req.body.username;  // form field is still named 'username'
  const password = req.body.password;

  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/login");
      return;
  }

  const result = await userCollection.find({ email }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

  if (result.length !== 1) {
      console.log("user not found");
      res.redirect("/login");
      return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
      console.log("correct password");
      req.session.authenticated = true;
      req.session.name = result[0].name;
      req.session.email = email;
      req.session.cookie.maxAge = expireTime;

      res.redirect('/');
  } else {
      console.log("incorrect password");
      res.redirect("/login");
  }
});

app.get('/logout', (req,res) => {
	req.session.destroy();
  res.redirect('/');
});

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
      return res.redirect('/');
  }

  const images = ['Ugly_fish.jpg', 'Surprise_Fish.png', 'Dotted_fish.webp'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <img src="/${randomImage}" alt=${randomImage} style="max-width: 500px;"><br>
      <a href="/">Home</a> | 
      <a href="/logout">Logout</a>`
    );
});

app.use((req, res) => {
  res.status(404).send('Page not found - 404');
});

(async () => {
  const db = await connectDB();
  app.locals.db = db;
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();