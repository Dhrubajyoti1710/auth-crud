const express=require('express')
const ejs=require('ejs')
const dotenv=require('dotenv')
const dbCon=require('./app/config/db')
const cors = require('cors')
const path=require('path')

dotenv.config()
const app=express();
dbCon()
app.use(cors({
    // origin: "http://localhost:3000",
    // credentials: true,
  }))

//templeteing engine ejs setup
app.set('view engine','ejs');
app.set('views','views')

//create static file
app.use(express.static(__dirname +'/public'))      
app.use('/uploads',express.static(path.join(__dirname,'/uploads')))
app.use('/uploads',express.static('uploads'))

app.use(express.urlencoded({extended:true}));
app.use(express.json());
//define routers
const ApiRouter=require('./app/router/ApiRouter')
app.use('/api',ApiRouter)

const AuthRouter=require('./app/router/AuthRouter')
app.use('/api/auth',AuthRouter)

const AdminRouter=require('./app/router/AdminRouter')
app.use('/api/admin',AdminRouter)


//listing port
const port=3003;
app.listen(port,()=>{
    console.log(`server running port http://localhost:${port}`);
    
})