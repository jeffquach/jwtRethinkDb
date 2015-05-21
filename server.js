var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var fs = require("fs");
var bcrypt = require("bcrypt");
var jwt    = require('jsonwebtoken');
var config = require('./config');
var User   = require('./app/models/user');
var crypto = require('crypto');

var port = process.env.PORT || 3000;

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// =======================
// routes ================
// =======================
// basic route
app.get('/', function(req, res) {
    res.send('Hello! The API is at http://localhost:' + port + '/api');
});
app.get("/setup",function(req,res){
    generateRefreshToken(function(id){
        darmish = new User({ 
            name: 'darmish', 
            password: 'darmish',
            admin: true,
            refresh_token:id 
        });
        // save the sample user
        darmish.save(function(err) {
            if (err) throw err;
            console.log('User saved successfully');
            res.json({ success: true, uuid: id});
        });
    })
})
function generateRefreshToken(cb){
    crypto.randomBytes(35, refreshTokenCallback(cb));
}
function refreshTokenCallback(cb){
    return function(err,buffer){
        if (err) throw err;
        var id = buffer.toString('hex');
        cb(id);
    }
}
function getKey(fileToRead,next,cb){
    fs.readFile(fileToRead,getKeyCallback(next,cb));
}
function getKeyCallback(next,cb){
    return function(err,data){
        if (err) {next(err)};
        cb(data)
    }
}
function comparePassword(user,valueToCompare,isPassword,req,res,next){
    user.comparePassword(valueToCompare,isPassword,comparePasswordCallback(user,req,res,isPassword,next));
}
function comparePasswordCallback(user,req,res,isPassword,next){
    return function(err,matchingPassword){
        if (err) {next(err)};
        if (!matchingPassword) {
            res.status(401).json({success:false,message:"Wrong password yo!"});
        }else{
            if (isPassword) {
                generateKey(user,res,next);
            }else{
                generateKeyAndRefreshToken(user,req,res,next);
            }
        }
    }
}
function generateKey(user,res,next){
    getKey("./private.pem",next,keyGenerationCallback(user,function(token){
        res.json({success:true,message:"Here's your token hater!",token:token});
    }))
}
function generateKeyAndRefreshToken(user,req,res,next){
    getKey("./private.pem",next,keyGenerationCallback(user,function(token){
        generateRefreshToken(function(refresh_token){
            var new_refresh_token = refresh_token.toString('hex');
            user.generateHashAndSalt(new_refresh_token,req,user,token,next);
        })
    }))
}
function keyGenerationCallback(user,cb){
    return function(file){
        var token = jwt.sign({user:user.name},file,{algorithm:"RS256",expiresInMinutes:1,ignoreExpiration:false});
        cb(token)
    }
}

// API ROUTES -------------------
var apiRoutes = express.Router();

apiRoutes.post("/authenticate",function(req,res,next){
    User.findOne({name: req.body.name}, function(err,user){
        if (err) {throw err;};
        if (!user) {
            res.json({success:false,message:"Authentication failed, probs a wrong password or somethang!"});
        }else if(user){
            comparePassword(user,req.body.password,true,req,res,next);
        }
    });
});

// Place middleware for jwt code above here to get the code to run for these routes that require the webtoken

apiRoutes.use(function(req,res,next){
    var token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (token) {
        getKey("./public.pem",next,function(cert){
            jwt.verify(token,cert,{algorithms:["RS256"],ignoreExpiration:false},function(err,decoded){
                if (err) {
                    var refresh_token = req.query.refresh_token || req.headers['x-refresh-token'];
                    var username = req.query.username;
                    if (username) {
                        User.findOne({name:username},function(err,user){
                            if (err) {next(err)};
                            if (!user) {
                                res.status(403).json({message:"That user doesn't exist!"});
                            }else{
                                comparePassword(user,refresh_token,false,req,res,next);
                            }
                        });
                    }
                    else{
                        return res.json({success:false,message:"Failed to authenticate token"});
                    }
                }else{
                    console.log("$$$ decoded object from jwt.verify callback is $$$:");
                    console.log(decoded);
                    req.decoded = decoded;
                    req.jammers = "Yo bro!";
                    next();
                }
            })
        })
    }else{
        return res.status(403).send({
            success: false,
            message: "No token son!"
        });
    }
});

apiRoutes.get("/",function(req,res){
    res.json({message: "Default API route",jwt: req.token, refresh_token: req.refresh_token});
});

apiRoutes.get("/users",function(req,res){
    User.find({},function(err,users){
        res.json({users:users,jwt: req.token, refresh_token: req.refresh_token});
    });
});
apiRoutes.get("/darmish",function(req,res){
    User.findOne({name:req.query.darmish},function(err,users){
        res.json({user:users});
    });
});

app.use("/api",apiRoutes);

app.listen(port);
console.log('Magic happens at http://localhost:' + port);