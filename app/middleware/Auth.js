const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');

const hashePassword=async(password)=>{
    try{
        const salt=10;
        const hashedPassword=await bcrypt.hash(password,salt);
        return hashedPassword;

    }catch(err){
        console.log(err);
    }
}

const AuthCheck=async(req,res,next)=>{
    const token= req.body.token || req.query.token || req.headers['x-access-token'];
    if(!token){
        return res.status(400).json({
            message:'Token is required for access this page'
        });
    }
    try{
        const decoded=jwt.verify(token, process.env.JWT_SECRECT)
        req.user=decoded;
       console.log('after login data',req.user);
       
       

    }catch(err){
       return res.status(400).json({
            message:'Invalid token Access'
        });
    }
    return next();

}



module.exports={hashePassword,AuthCheck}