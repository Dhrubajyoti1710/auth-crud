const express= require('express');
const AuthController = require('../controller/AuthController');
const { AuthCheck } = require('../middleware/Auth');
const router=express.Router();

router.get('/dashboard',AuthCheck,AuthController.dashboard);

module.exports=router;