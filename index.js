// Import express and ejs
var express = require ('express')
var ejs = require('ejs')
const path = require('path')
var mysql = require('mysql2');
var session = require ('express-session')
const expressSanitizer = require('express-sanitizer');
require('dotenv').config();

// Create the express application object
const app = express()
const port = 8000

 /*Define the database connection pool
const db = mysql.createPool({
    host: 'localhost',
    user: 'berties_books_app',
    password: 'qwertyuiop',
    database: 'berties_books',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});
*/
// Define the database connection pool
const db = mysql.createConnection({
    host: process.env.DB_HOST,         // Fetched from .env
    user: process.env.DB_USER,         // Fetched from .env
    password: process.env.DB_PASSWORD, // Fetched from .env
    database: process.env.DB_NAME      // Fetched from .env
});

db.connect(function(err) {
    if (err) throw err;
    console.log("Database Connected!");
});
global.db = db;

// Create a session
app.use(session({
    secret: 'somerandomstuff',
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 600000
    }
}))

// Create an input sanitizer
app.use(expressSanitizer());

// Tell Express that we want to use EJS as the templating engine
app.set('view engine', 'ejs')

// Set up the body parser 
app.use(express.urlencoded({ extended: true }))

// Set up public folder (for css and static js)
app.use(express.static(path.join(__dirname, 'public')))

// Define our application-specific data
app.locals.shopData = {shopName: "Bertie's Books"}

// Load the route handlers
const mainRoutes = require("./routes/main")
app.use('/', mainRoutes)

// Load the route handlers for /users
const usersRoutes = require('./routes/users')
app.use('/users', usersRoutes)

// Load the route handlers for /books
const booksRoutes = require('./routes/books')
app.use('/books', booksRoutes)

// Start the web app listening
app.listen(port, () => console.log(`Example app listening on port ${port}!`))