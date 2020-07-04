const app = require('express')();
const cors = require('cors');
const bodyParser = require('body-parser');

const PORT = 8000;

app.get('/signup', (req, res) => {
  console.log('hello');
  res.send('hello');
});

app.listen(8000, () => console.log('Server is listening...'));
