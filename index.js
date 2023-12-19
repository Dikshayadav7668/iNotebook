const connectToMongo = require('./db')

connectToMongo();
const express = require('express')
const app = express()
const port = 5000

var cors = require('cors')


app.use(cors())

app.use(express.json())

/*app.get('/', (req, res) => 
  res.send('Hello World!')
)*/
//Available Routes
app.use('/api/auth',require('./routes/auth'))
app.use('/api/notes',require('./routes/notes'))

app.listen(port, () => {
  console.log(`iNotebook backend listening on port at http://localhost:${port}`)
})