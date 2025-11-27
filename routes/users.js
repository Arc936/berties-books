// Create a new router
const express = require("express")
const router = express.Router()
const bcrypt = require('bcrypt')
const { check, validationResult } = require('express-validator');

const redirectLogin = (req, res, next) => {
    if (!req.session.userId ) {
      res.redirect('./login') // redirect to the login page
    } else { 
        next (); // move to the next middleware function
    } 
}

// Add this to your Express router file (where you define other routes)
// Route to display the login form
router.get('/login', function (req, res, next) {
    // Renders the login form view
    res.render('login.ejs'); 
});

// Function to log the attempt (place this outside the route, or ensure 'db' is in scope)
function logLoginAttempt(username, success, callback) {
    const sqlquery = "INSERT INTO login_attempts (username, success) VALUES (?, ?)";
    db.query(sqlquery, [username, success], callback);
}

router.post('/loggedin', function (req, res, next) {
    const { username, password } = req.body;

    // 1. Find the user... (as before)
    const sqlquery = "SELECT hashedPassword FROM users WHERE username = ?";
    
    db.query(sqlquery, [username], (err, results) => {
        if (err) return next(err);

        // Case 1: User NOT Found (Immediate Failure)
        if (results.length === 0) {
            // Log failure for the provided username
            logLoginAttempt(username, false, (logErr) => {
                if (logErr) console.error('Audit log failed:', logErr);
                res.send(`<h1>Login Failed</h1><p>User **${username}** not found.</p>`);
            });
            return;
        }

        const storedHashedPassword = results[0].hashedPassword;

        // 2. Compare the password... (as before)
        bcrypt.compare(password, storedHashedPassword, (compareErr, isMatch) => {
            if (compareErr) return next(compareErr);

            let successStatus = isMatch; // true or false

            // Save user session here, when login is successful
            req.session.userId = req.body.username;


            // 3. Log the audit attempt BEFORE sending the response
            logLoginAttempt(username, successStatus, (logErr) => {
                if (logErr) console.error('Audit log failed:', logErr);
                
                // 4. Send the final response
                if (successStatus) {
                    res.send(`<h1>Login Successful!</h1><p>Welcome back, **${username}**.</p>`);
                } else {
                    res.send(`<h1>Login Failed</h1><p>Incorrect password for user **${username}**.</p>`);
                }
            });
        });
    });
});

router.get('/logout', redirectLogin, (req,res) => {
    req.session.destroy(err => {
    if (err) {
        return res.redirect('./')
    }
    res.send('you are now logged out. <a href='+'./'+'>Home</a>');
    })
})


router.get('/list', redirectLogin, function(req, res, next) {
    // 💡 IMPORTANT: Explicitly select the columns you need, 
    // omitting the sensitive 'hashedPassword' column.
    let sqlquery = "SELECT userId, username, firstName, lastName, email FROM users ORDER BY lastName, firstName";
    
    // Execute the SQL query
    db.query(sqlquery, (err, users) => {
        if (err) {
            console.error('Database error in /users/list:', err);
            // Pass the error to the Express error handler
            return next(err);
        }
        
        // Render the new view/template page, passing the list of users
        res.render("users_list", { users: users });
    });
});

router.get('/register', function (req, res, next) {
    res.render('register.ejs')
})

router.post('/registered',
    // 1. Validation Middleware Array (as before)
    [
        check('email').isEmail(), 
        check('username').isLength({ min: 5, max: 20})
    ],
    // 2. Main Route Handler
    function (req, res, next) {
        const errors = validationResult(req);
                // --- B. Sanitize Inputs (Place the sanitization here) ---
        // Sanitize 
        const sanitizedFirstName = req.sanitize(req.body.first); 

        const sanitizedLastName = req.sanitize(req.body.last);

        // --- A. Handle Validation Errors ---
        if (!errors.isEmpty()) {
            return res.render('./register'); 
        }

        // --- C. Execute Registration Logic ---
        else { 
            const saltRounds = 10;
            const plainPassword = req.body.password;
            
            bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
                if (err) {
                    console.error('Password hashing failed:', err);
                    return next(err);
                }

                // 3. Store the user in the database.
                const sqlquery = "INSERT INTO users (username, firstName, lastName, email, hashedPassword) VALUES (?, ?, ?, ?, ?)";
                
                // Use the SANITIZED values for database insertion
                const userDetails = [
                    req.body.username, // Assuming username is handled by check()
                    sanitizedFirstName, 
                    sanitizedLastName, 
                    req.body.email, 
                    hashedPassword
                ];
                
                db.query(sqlquery, userDetails, (dbError, result) => {
                    if (dbError) {
                        console.error('Database insertion error:', dbError);
                        return next(dbError); 
                    }
                    
                    // 4. Use the SANITIZED values for the success message (if sending one)
                    const successMessage = 'Hello '+ sanitizedFirstName + ' '+ sanitizedLastName +' you are now registered!';
                    
                    res.redirect('/login'); 
                });
            });
        }
    }
);

// Route to display the full audit history
router.get('/audit',redirectLogin, function(req, res, next) {
    // Select all fields from the audit table, ordered by time (most recent first)
    const sqlquery = "SELECT username, attemptTime, success FROM login_attempts ORDER BY attemptTime DESC";
    
    db.query(sqlquery, (err, attempts) => {
        if (err) {
            console.error('Database error in /users/audit:', err);
            return next(err);
        }
        
        // Render the new view/template page, passing the list of attempts
        res.render("audit.ejs", { attempts: attempts });
    });
});
// Export the router object so index.js can access it
module.exports = router