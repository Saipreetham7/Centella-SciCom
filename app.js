require('dotenv').config()
const express = require('express');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require('express-session');
const mongoose = require("mongoose");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const saltRounds =10; 


const app = express();
app.set('view engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

const JWT_SECRET = "some super secret";

mongoose.connect("mongodb://localhost:27017/centellaDB",{useNewUrlParser: true});

const userSchema = {
    name : String,
    email : String,
    password : String
};

const smeSchema = {
    name : String,
    email : String,
    password : String
};


const User = new mongoose.model("User",userSchema);
const sme = new mongoose.model("sme",smeSchema);

app.use(session({   
    resave: false,
    saveUninitialized: true,
    secret: 'SECRET' 
  }));
  

app.get("/",(req,res)=>{
    res.render("home");
});

app.get("/researcher",(req,res)=>{
    res.render("researcher");
});

app.get("/sme",(req,res)=>{
    res.render("sme");
});

app.get("/userlogin",(req,res)=>{
    res.render("userLogin");
});

app.get("/smeLogin",(req,res)=>{
    res.render("smeLogin")
});

app.get("/userRegister",(req,res)=>{
    res.render("userRegister");
});

app.get("/smeRegister",(req,res)=>{
    res.render("smeRegister");
});

app.get("/userDashboard",(req,res)=>{
    res.render("userDashboard");
});

app.get("/smeDashboard",(req,res)=>{
    res.render("smeDashboard");
});



// Google Authentication

/*  PASSPORT SETUP  */

var userProfile;

app.use(passport.initialize());
app.use(passport.session());


passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
        done(null, user);
}); 


/*  Google AUTH  */
 
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/callback",passReqToCallback:true
    },
    function(request, accessToken, refreshToken, profile, done) {
        return done(null, profile);
    }
)); 

app.get("/failed", (req, res) => {
    res.render('error.ejs');
});

app.get('/auth/google',
    passport.authenticate('google', {
            scope:
                ['email', 'profile']
        }
    ));

app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failed',
    }),
    function (req, res) {
        res.redirect('/userDashboard')

    }
);

// LinkedIn Authentication


passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_CLIENT_ID,
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  callbackURL: "http://127.0.0.1:3000/auth/linkedin/callback",
  scope: ['r_emailaddress', 'r_liteprofile'],
}, function(accessToken, refreshToken, profile, done) {
  process.nextTick(function () {
    return done(null, profile);
  });
}));

app.get('/auth/linkedin',
  passport.authenticate('linkedin', { scope: ['r_emailaddress', 'r_liteprofile']  }),
  function(req, res){
    // The request will be redirected to LinkedIn for authentication, so this
    // function will not be called.
  });

app.get('/auth/linkedin/callback',
  passport.authenticate('linkedin', {
    successRedirect: '/userDashboard',
    failureRedirect: '/userLogin'
}));

//post methods

//User login & Registration
app.post("/userRegister",(req,res)=>{
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            name : req.body.name,
            email : req.body.username,
            password : hash
        });
    
        newUser.save(function(err){
            if(err){
                console.log(err);
            }
            else{
                res.redirect('/userLogin');
            }
        });
    });
});

app.post("/userLogin",(req,res)=>{
    const username = req.body.username;
    const password = req.body.password;
    
    User.findOne({email: username},function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result){
                    if(result==true)
                        res.redirect("/userDashboard");
                    else
                        res.redirect("/userLogin");
                })
            }
        }
    });
});

// SME Login and Registration

app.post("/smeRegister",(req,res)=>{
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new sme({
            name : req.body.name,
            email : req.body.username,
            password : hash
        });
    
        newUser.save(function(err){
            if(err){
                console.log(err);
            }
            else{
                res.redirect('/smeLogin');
            }
        });
    });
});

app.post("/smeLogin",(req,res)=>{
    const username = req.body.username;
    const password = req.body.password;
    
    sme.findOne({email: username},function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result){
                    if(result==true)
                        res.redirect("/smeDashboard");
                    else
                        res.redirect("/smeLogin");
                })
            }
        }
    });
});


app.get("/forgot-password",(req,res)=>{
    res.render('forgot-password'); 
});

app.post("/forgot-password",(req,res)=>{
    const email = req.body.email;
    User.findOne({email: email},function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            const secret = JWT_SECRET + foundUser.password;
            const payload = {
                email : foundUser.email
            }
            const token = jwt.sign(payload , secret, {expiresIn: '5m'});
            const link = `http://localhost:3000/reset-password/${email}/${token}`;
            const transporter = nodemailer.createTransport({
                service : "gmail",
                auth : {
                    user : "saipreetham3022@gmail.com",
                    pass : "saipreetham3"
                }
            });

            const options = {
                from : "saipreetham3022@gmail.com",
                to : foundUser.email,
                subject : "Reset Password Link",
                text : " Reset Password Link Click Here : " + link
            };

            transporter.sendMail(options, (err, info) => {
                if(err)
                    console.log(err);
                else{
                    console.log("Sent : " + info.response);
                }
            });
            console.log(link);
            res.send("Password reset link has been sent to your email...");
        }
    });
    
});

app.get("/reset-password/:email/:token",(req,res)=>{
    const {email,token} = req.params;
    User.findOne({email: email},function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            const secret = JWT_SECRET + foundUser.password;
            try {
                const payload = jwt.verify(token, secret);
                res.render("reset-password",{email : foundUser.email});
            } catch (error) {
                console.log(error.message);
                res.send(error.message);
            }
        }
    });
});

app.post("/reset-password/:email/:token",(req,res)=>{
    const {email,token} = req.params;
    var {password,password2} = req.body
    // res.send(req.params);
    User.findOne({email: email},function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            const secret = JWT_SECRET + foundUser.password;
            try {
                const payload = jwt.verify(token, secret);
                bcrypt.hash(password, saltRounds, (hash) => {
                    password = hash;
                  
                    // then update
                    User.updateOne({email : email}, req.body, function(err,foundUser){
                        if(err)
                            console.log(err);
                        else{
                            foundUser.password = password;
                            res.render("userLogin");
                        }
                    });
                  });  
                
            } catch (error) {
                console.log(error.message);
                res.send(error.message);
            }
        }
    });
});





app.listen(3000,function(){
    console.log("Server Started at 3000");
});

