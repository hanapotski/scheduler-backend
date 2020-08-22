const express = require('express');
const app = express();
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

const corsConfig = {
  origin: 'http://localhost:3000',
  methods: 'GET,PUT,POST,DELETE',
  credentials: true,
  allowedHeaders: 'Origin,X-Requested-With,Content-Type,Accept,Cookie',
  preflightContinue: false,
  optionsSuccessStatus: 204,
};

dotenv.config();
app.use(cors(corsConfig));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(process.env.SECRET));

const PORT = process.env.PORT || 5000;
const dbUrl = process.env.DB_URL;

mongoose.connect(dbUrl, { useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function () {
  console.log('connected to db!');
});

const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      trim: true,
    },
    password: { type: String, required: true },
    isVerified: Boolean,
    lastLogin: Date,
  },
  { timestamps: { createdAt: 'created_at' } }
);

const EventSchema = new mongoose.Schema(
  {
    createdBy: String,
    modifiedBy: String,
    updatedAt: Date,
    eventDate: { type: Date, required: true },
    eventName: { type: String, required: true },
    leader: { type: String, required: true },
    backups: String,
    keyboardist: String,
    acousticGuitar: String,
    electricGuitar: String,
    drums: String,
    keys: String,
    bass: String,
    other: [{ name: String, instrument: String }],
  },
  { timestamps: { createdAt: 'createdAt' } }
);

// https://www.mongodb.com/blog/post/password-authentication-with-mongoose-part-1
UserSchema.pre('save', function (next) {
  const SALT_WORK_FACTOR = 10;
  var user = this;

  // only hash the password if it has been modified (or is new)
  if (!user.isModified('password')) return next();

  // generate a salt
  bcrypt.genSalt(SALT_WORK_FACTOR, function (err, salt) {
    if (err) return next(err);

    // hash the password using our new salt
    bcrypt.hash(user.password, salt, function (err, hash) {
      if (err) return next(err);

      // override the cleartext password with the hashed one
      user.password = hash;
      next();
    });
  });
});

function comparePassword(sentPassword, foundPassword, cb) {
  bcrypt.compare(sentPassword, foundPassword, function (err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
}

const User = mongoose.model('User', UserSchema);
const Event = mongoose.model('Event', EventSchema);

// ROUTES
//==================================================
app.get('/', (req, res) => {
  res.send('hi');
});
app.post('/signin', (req, res) => {
  // fetch user and test password verification
  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) {
      res.send({
        error: true,
        message: 'Something went wrong. Please contact the admin',
      });
    }
    if (!user) {
      res.send({ error: true, message: 'User does not exist!' });
      return;
    }

    comparePassword(req.body.password, user.password, function (err, isMatch) {
      if (err) throw err;
      if (!isMatch) {
        res.send({ error: 'Password incorrect!' });
      } else {
        res.send({ message: 'success', data: user });
      }
    });
  }).catch((err) => {
    console.log('Error!', err);
    res.send({ error: true, message: err });
  });
});

app.post('/signup', (req, res) => {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) throw err;
    if (user) {
      res.send({
        error:
          'User already exist! Please use a different email or contact the admin.',
      });
    } else {
      User.create({ ...req.body, isVerified: false })
        .then((data) => {
          res.status('200').send({ message: 'success', data });
        })
        .catch((err) => {
          console.log('Error!', err);
          res.send({ error: true, message: err });
        });
    }
  });
});

app.post('/addEvent', (req, res) => {
  console.log(req.body);
  Event.create(req.body)
    .then((data) => {
      console.log(data);
      res.status('200').send({ message: 'success', data });
    })
    .catch((err) => {
      console.log('Error!', err);
      res.send({ error: true, message: err });
    });
});

app.get('/events', (req, res) => {
  Event.find()
    .then((data) => {
      res.status('200').send({ message: 'success', data });
    })
    .catch((err) => {
      console.log('Error!', err);
      res.send({ error: true, message: err });
    });
});

app.put('/updateEvent', async (req, res) => {
  Event.findByIdAndUpdate({ _id: req.body._id }, req.body, function (
    err,
    result
  ) {
    if (err) {
      res.send({ error: true, message: err });
    } else {
      console.log(result);
      res.send({ message: 'success' });
    }
  });
});

app.listen(5000, () => console.log('Server is listening...'));
