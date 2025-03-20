const express=require('express');
const AuthController = require("../controller/AuthController");
const { AuthCheck } = require('../middleware/Auth');
const router=express.Router();

router.post('/register',AuthController.register);
router.post('/verify-otp',AuthController.verifyOtp);
router.post('/login',AuthController.login);
router.post('/update-password',AuthCheck,AuthController.updatePassword);
router.post('/forgot-password',AuthController.forgetPassword);
router.post('/reset-password/:token',AuthController.resetPassword);
router.get('/profile',AuthCheck,AuthController.userProfile);



module.exports=router;