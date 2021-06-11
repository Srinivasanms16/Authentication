const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs")
const path = require('path');
const cors = require("cors");
const cookie = require("cookie-parser");
const session = require("express-session");
const morgan = require("morgan");
const fs = require('fs');
const mongodbsessionStore = require('connect-mongodb-session')(session);

const server = express();

//parse the body.
server.use(express.json());
server.use(express.urlencoded());
server.use(cors());

//first we need to create the stream 
const writeStream = fs.createWriteStream(path.join(__dirname,"logfile"),{_flags:'a'})
//In the morgan either we can send predefind format such as common, combained, tiny or dev
//or
//we can create our own format like below.
server.use(morgan(":method :url :status :response-time[digits]",{stream:writeStream}))

//using cookie parser create cookie object and attach to response so hearafter for every request will can access the cookie
server.use(cookie());
//we are using cookie to store sessionID , all session relates data are stored in server side.
//creating store , this store will point the mongodb 
const store = new mongodbsessionStore({
    uri: 'mongodb+srv://sa:sa@cluster0.94ahr.mongodb.net/Authentication?retryWrites=true&w=majority',
    collection: 'Sessions'
  });
   
server.use(session({secret:"key1",store}));

//to server the static files.
const staticfiles = path.join(__dirname,"public");
server.use(express.static(staticfiles));

function servermethods(client)
{
    //Creating new user.
    server.post("/signup",async (req,res)=>{
       const password = await bcrypt.hash(req.body.password,10);
       let data = {...req.body,password,role:"customer"}; 
       const result = await client.db("Authentication").collection("UserInfo").insertOne(data)
       res.send(result.ops);
    })

    //SignIn
    server.post("/signin",async (req,res,next)=>{

        //http://localhost:3000/signin
        //or
        // http://localhost:3000/signin?redirectURL=https://www.youtube.com/
        
        const result = await client.db("Authentication").collection("UserInfo").findOne({email:req.body.email});
        if(result)
        {
        const isSuccess = await bcrypt.compare(req.body.password,result.password)
        if(isSuccess)
        {
            const token = jwt.sign({fname:result.fname,email:result.email},"nithin");
            if(req.query.redirectURL)
            {
                //if we have redirect URL then we will append the token at the end and pass it back as response so that client can use that.
                const rurl = `${req.query.redirectURL}?token=${encodeURIComponent(token)}`;
                res.status(200).send(rurl)
            }
            //if the querystring dosent have redirect URL then we check the Session
            if(req.session.redirectURL)
            {
                const rurl = `${req.session.redirectURL}?token=${encodeURIComponent(token)}`;
                res.status(200).send(rurl);
                return;
            }
            //console.log(req.cookies.redirectURL);
            if(req.cookies.redirectURL)
            {
                const rurl = `${req.cookies.redirectURL}?token=${encodeURIComponent(token)}`;
                res.status(200).send(rurl);
                return
            }
            res.status(200).send(token);
        }
        else
        {
            res.status(401).send("username and password or not matching");
        }
    }
    else
    {
        res.status(401).send("register");
    }
    })

    //Verify User.
    server.post("/verify",(req,res,next)=>{
        const isVerified = jwt.verify(req.body.token,"nithin");
        console.log(isVerified);
        if(isVerified)
        {
            res.sendStatus(200);
        }
        else
        {
            res.sendStatus(403);
        }
    })

    //we can able to modifiy the req.params and req.queruy in the middleware.ki/huN(/":")
    server.get("/",
      (req,res,next)=>{
          console.log(JSON.stringify(req.params));
        //url localhost:3000?redirectURL=https://www.youtube.com/
        //we are creating the session for the user and save the redirectURL.
        //we are using cookie to store the sessionID.
        if( req.session.redirectURL == undefined)
        {
           req.session.redirectURL = req.query.redirectURL;
        }
        
        if(req.cookies.redirectURL == undefined)
        {
        res.cookie("redirectURL",req.query.redirectURL);
        }
        res.sendFile(path.join(__dirname,"pages","login.html"));
    })

    server.get("/register",(req,res,next)=>{
        res.sendFile(path.join(__dirname,"pages","signup.html"))
    })

    //overall error cache mechnisum
    server.use((error,req,res,next)=>{
       res.status(500).send("Issue in server");
    })
    server.listen(process.env.PORT || 3000,()=>{
        console.log(`Server is listening in port 3000 !`)
    })
}
 
//Connecting to MongoDb Server.
try{
//this start of the application.
 MongoClient.connect("mongodb+srv://sa:sa@cluster0.94ahr.mongodb.net/Authentication?retryWrites=true&w=majority",{ useUnifiedTopology: true})
 .then(client=>{
//Sending Client object so that server can access those.    
servermethods(client);
}).catch(error=>{
    console.log(error);
})

}
catch(error){
console.log(error);
}




