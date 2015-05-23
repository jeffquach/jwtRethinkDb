var thinky = require('../util/thinky.js');
var bcrypt = require("bcrypt");
var type = thinky.type;

var User = thinky.createModel("User",{
	name: type.string(),
	password: type.string(),
	admin: type.boolean(),
	refresh_token: type.string(),
	status: type.string().default("active")
});
User.pre("save",passwordCallback());
User.pre("save",refreshTokenCallback());
User.define("comparePassword", function(candidatePassword,isPassword,cb){
    var valueToCompare = isPassword? this.password : this.refresh_token;
    bcrypt.compare(candidatePassword,valueToCompare,function(err,isMatch){
        if (err) {return cb(err);}
        cb(null,isMatch);
    });
});
User.define("generateHashAndSalt", function(valueToHash,req,user,token,next){
    generateHash(valueToHash,next,function(hash){
    	console.log("Hash is: "+hash);
        console.log("user.id: "+(user.id));
        User.get(user.id).update({refresh_token:hash}).run(function(err){
            if (err) {throw next(err);};
            req.token = token;
            req.refresh_token = valueToHash;
            next();
        });   
    })
});
function passwordCallback(){
    return function(next){
        var user = this;
        //if (!user.isModified("password")) {return next();}
        generateHash(user.password,next,function(hash){
            user.password = hash;
            next();
        })
    }
}
function refreshTokenCallback(){
    return function(next){
        var user = this;
        //if (!user.isModified("refresh_token")) {return next();}
        generateHash(user.refresh_token,next,function(hash){
            user.refresh_token = hash;
            next();
        })
    }
}
function generateHash(valueToHash,next,cb){
    bcrypt.hash(valueToHash,8,generateHashCallback(next,cb));
}
function generateHashCallback(next,cb){
    return function(err,hash){
        if (err) {throw next(err)};
        cb(hash);
    }
}
module.exports = User;