// Create a new router
const express = require("express")
const router = express.Router()

// Handle our routes
router.get('/',function(req, res, next){
    res.render('index.ejs')
});

router.get('/about',function(req, res, next){
    res.render('about.ejs')
});

router.get('/users', (req, res) => {
    // Send a 301 (Permanent) or 302 (Temporary) redirect status.
    // 302/307 (Temporary) is generally safer unless you are certain
    // the '/users' path will never be used again.
    res.redirect(302, '/');
});

// Export the router object so index.js can access it
module.exports = router