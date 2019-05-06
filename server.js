const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcryptjs');
const redis = require('connect-redis')(session);

const User = require('./database/models/User');
const PORT = process.env.PORT || 8080;
const ENV = process.env.NODE_ENV || 'development';
const SESSION_SECRET = process.env.SESSION_SECRET || 'keyboard cat';
const saltRounds = 12;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  store: new redis({ url: 'redis://redis-server:6379', logErrors: true }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));
app.use(express.static('public'));

// PASSPORT STUFFFFFFFFFF
app.use(passport.initialize());
app.use(passport.session());

// after login
passport.serializeUser((user, done) => {
  console.log('serializing');
  return done(null, {
    id: user.id
  });
});

// after every request
passport.deserializeUser((user, done) => {
  console.log('deserializing');
  new User({ id: user.id }).fetch()
  .then(dbUser => {
    dbUser = dbUser.toJSON();
    return done(null, {
      id: dbUser.id,
      username: dbUser.username
    });
  })
  .catch((err) => {
    console.log(err);
    return done(err);
  });
});

passport.use(new LocalStrategy(function(username, password, done) {
  return new User({ username: username })
  .fetch()
  .then ((user) => {
    user = user.toJSON();
    console.log(user);

    if (user === null) {
      return done(null, false, {message: 'bad username or password'});
    }
    else {
      bcrypt.compare(password, user.password)
      .then((res) => {
        if (res) { return done(null, user); }
        else {
          return done(null, false, {message: 'bad username or password'});
        }
      });
    }
  })
  .catch(err => {
    console.log('error: ', err);
    return done(err);
  });
}));

app.post('/register', (req, res) => {
  bcrypt.genSalt(saltRounds, (err, salt) => {
    if (err) { console.log(err); }

    bcrypt.hash(req.body.password, salt, (err, hash) => {
      if (err) { console.log(err); }

      return new User({
        username: req.body.username,
        password: hash
      })
      .save()
      .then((user) => {
        console.log(user);
        res.redirect('/login.html');
      })
      .catch((err) => {
        console.log(err);
        return res.send('Error Creating account');
      });
    });
  });
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/secret',
  failureRedirect: '/login.html'
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.sendStatus(200);
});

function isAuthenticated (req, res, next) {
  if(req.isAuthenticated()) { next();}
  else { res.redirect('/'); }
}

app.get('/secret', isAuthenticated, (req, res) => {
  console.log('req.user: ', req.user);
  console.log('req.user id', req.user.id);
  console.log('req.username', req.user.username);
  res.send('you found the secret!');
});


app.get('/smoke', (req, res) => {
  return res.send('smoke test 2');
});


app.listen(PORT, () => {
  console.log(`Server running on port: ${PORT}`);
  console.log('this is docker');
});
