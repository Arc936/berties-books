// Create a new router
const express = require("express")
const router = express.Router()


router.get('/search', function (req, res, next) {
    // Renders the search results page but passes an empty array and blank term 
    // so the user sees the search bar and the '0 found' message.
    res.render('search_results', { books: [], searchTerm: '' });
});


// Route 2: POST /search (Executes the advanced search query)
router.post('/search', function (req, res, next) {
    // Get the search term from the form submission
    const searchTerm = req.body.searchTerm;

    // Advanced Search using SQL LIKE with wildcards (%):
    // This finds any book name that contains the search term anywhere within it.
    const sqlquery = "SELECT name, price FROM books WHERE name LIKE ?";
    
    // The % characters enable partial matching. For example, if searchTerm is 'World', 
    // the value passed to the database is '%World%'.
    const partialSearchTerm = `%${searchTerm}%`;

    db.query(sqlquery, [partialSearchTerm], (err, books) => {
        if (err) {
            console.error('Search database error:', err);
            next(err); 
        } else {
            // Render the search results page, passing the results and the original search term
            res.render('search_results', { 
                books: books, 
                searchTerm: searchTerm // Pass the original term back to display in the header
            });
        }
    });
});

router.get('/list', function(req, res, next) {
    let sqlquery = "SELECT * FROM books"; // query database to get all the books
    // execute sql query
    db.query(sqlquery, (err, result) => {
        if (err) {
           next(err)
        }
        res.render("list.ejs", {books:result})
    });
});

router.get('/addbook', function (req, res, next) {
    // Renders the input form
    res.render('addbook'); 
});


router.post('/bookadded', function (req, res, next) {
    // saving data in database
    let sqlquery = "INSERT INTO books (name, price) VALUES (?,?)"
    // execute sql query
    let newrecord = [req.body.name, req.body.price]
    
    db.query(sqlquery, newrecord, (err, result) => {
        if (err) {
            next(err)
        }
        else {
            // It's a good idea to redirect back to the form or the main list after success
            res.send('This book is added to database, name: '+ req.body.name + ' price '+ req.body.price);
        }
    })
});

// Add this new route to your router file (e.g., routes/books.js)

router.get('/bargainbooks', function (req, res, next) {
    // Selects books where the price is strictly less than 20
    const sqlquery = "SELECT name, price FROM books WHERE price < 20 ORDER BY price ASC";

    db.query(sqlquery, (err, books) => {
        if (err) {
            console.error('Bargain books database error:', err);
            // Pass the error to the error handler
            next(err); 
        } else {
            // Render the new bargainbooks EJS file, passing the filtered results
            res.render('bargainbooks', { books: books });
        }
    });
});

// Add this new route to your router file (e.g., routes/books.js)

router.get('/bargainbooks', function (req, res, next) {
    // Selects books where the price is strictly less than 20
    const sqlquery = "SELECT name, price FROM books WHERE price < 20 ORDER BY price ASC";

    db.query(sqlquery, (err, books) => {
        if (err) {
            console.error('Bargain books database error:', err);
            // Pass the error to the error handler
            next(err); 
        } else {
            // Render the new bargainbooks EJS file, passing the filtered results
            res.render('bargainbooks', { books: books });
        }
    });
});

// Add this new route to your router file (e.g., routes/books.js)

router.get('/bargainbooks', function (req, res, next) {
    // Selects books where the price is strictly less than 20
    const sqlquery = "SELECT name, price FROM books WHERE price < 20 ORDER BY price ASC";

    db.query(sqlquery, (err, books) => {
        if (err) {
            console.error('Bargain books database error:', err);
            // Pass the error to the error handler
            next(err); 
        } else {
            // Render the new bargainbooks EJS file, passing the filtered results
            res.render('bargainbooks', { books: books });
        }
    });
});

// Add this new route to your router file (e.g., routes/books.js)

router.get('/bargainbooks', function (req, res, next) {
    // Selects books where the price is strictly less than 20
    const sqlquery = "SELECT name, price FROM books WHERE price < 20 ORDER BY price ASC";

    db.query(sqlquery, (err, books) => {
        if (err) {
            console.error('Bargain books database error:', err);
            // Pass the error to the error handler
            next(err); 
        } else {
            // Render the new bargainbooks EJS file, passing the filtered results
            res.render('bargainbooks', { books: books });
        }
    });
});

// Export the router object so index.js can access it
module.exports = router
