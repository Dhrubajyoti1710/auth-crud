const User = require('../model/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { hashePassword } = require('../middleware/Auth');
const sendEmailVerificationOTP = require('../helper/sendEmailVerificationOTP');
const  transporter  = require("../config/emailConfig")
const EmailVerifyModel = require('../model/otpModel')

class AuthController {
    async register(req, res) {
        try {
            const { name, email, phone, password, role } = req.body;
            if (!name || !email || !phone || !password) {
                return res.status(400).json({
                    message: 'All fields are required'
                })
            }
            const existUser = await User.findOne({ email });
            if (existUser) {
                return res.status(400).json({
                    message: 'User already exists',
                    status: 400
                })
            }
            const hashedPassword = await hashePassword(password);
            const userData = await new User({
                name,
                phone,
                email,
                password: hashedPassword,
                role
            })

            const newData = await userData.save();
            sendEmailVerificationOTP(req, userData)

            return res.status(201).json({
                message: 'User created successfully. Please verify your email',
                user: newData,
                status: 201
            });
        } catch (err) {
            return res.status(400).json({
                message: 'User not created',
                error: err.message
            });

        }
    }

    async verifyOtp(req, res) {
        try {
            const { email, otp } = req.body;
            // Check if all required fields are provided
            if (!email || !otp) {
                return res.status(400).json({ status: false, message: "All fields are required" });
            }
            const existingUser = await User.findOne({ email });

            // Check if email doesn't exists
            if (!existingUser) {
                return res.status(404).json({ status: "failed", message: "Email doesn't exists" });
            }

            // Check if email is already verified
            if (existingUser.is_verified) {
                return res.status(400).json({ status: false, message: "Email is already verified" });
            }
            // Check if there is a matching email verification OTP
            const emailVerification = await EmailVerifyModel.findOne({ userId: existingUser._id, otp });
            if (!emailVerification) {
                if (!existingUser.is_verified) {
                    // console.log(existingUser);
                    await sendEmailVerificationOTP(req, existingUser);
                    return res.status(400).json({ status: false, message: "Invalid OTP, new OTP sent to your email" });
                }
                return res.status(400).json({ status: false, message: "Invalid OTP" });
            }
            // Check if OTP is expired
            const currentTime = new Date();
            // 15 * 60 * 1000 calculates the expiration period in milliseconds(15 minutes).
            const expirationTime = new Date(emailVerification.createdAt.getTime() + 15 * 60 * 1000);
            if (currentTime > expirationTime) {
                // OTP expired, send new OTP
                await sendEmailVerificationOTP(req, existingUser);
                return res.status(400).json({ status: "failed", message: "OTP expired, new OTP sent to your email" });
            }
            // OTP is valid and not expired, mark email as verified
            existingUser.is_verified = true;
            await existingUser.save();

            // Delete email verification document
            await EmailVerifyModel.deleteMany({ userId: existingUser._id });
            return res.status(200).json({ status: true, message: "Email verified successfully" });


        } catch (error) {
            console.error(error);
            res.status(500).json({ status: false, message: "Unable to verify email, please try again later" });
        }


    }

    async login(req, res) {
        try {
            const { email, password } = req.body;
            User.validate(email, password)
            if (!email || !password) {
                return res.status(400).json({
                    message: 'All fields are required'
                });
            }
            const existUser = await User.findOne({ email });
            if (!existUser) {
                return res.status(400).json({
                    message: 'User not found'
                });
            }
            // Check if user verified
            if (!existUser.is_verified) {
                return res.status(401).json({ status: false, message: "Your account is not verified" });
            }

            const isPasswordMatch = await bcrypt.compare(password, existUser.password);
            if (!isPasswordMatch) {
                return res.status(400).json({
                    message: 'Invalid password'
                });
            }

            const token = jwt.sign({
                id: existUser._id,
                name: existUser.name,
                email: existUser.email,
                phone: existUser.phone,
                role: existUser.role
            }, process.env.JWT_SECRECT || "kdjfkgkdfksdgfkdsgfskd", { expiresIn: "1h" })


            if (isPasswordMatch && existUser.role !== 'admin') {
                return res.status(200).json({
                    message: 'User logged in successfully',
                    title: "user",
                    user: {
                        id: existUser._id,
                        name: existUser.name,
                        email: existUser.email,
                        phone: existUser.phone,
                        role: existUser.role,
                        is_verified: existUser.is_verified
                    },
                    token: token,
                    status: 200,
                });
            }
            if (isPasswordMatch && existUser.role === 'admin') {
                return res.status(200).json({
                    message: 'Admin logged in successfully',
                    title: "admin",
                    user: {
                        id: existUser._id,
                        name: existUser.name,
                        email: existUser.email,
                        phone: existUser.phone,
                        role: existUser.role,
                        is_verified: existUser.is_verified
                    },
                    token: token,
                    status: 200,
                });
            }

        } catch (err) {
            return res.status(400).json({
                message: 'login failed',
                error: err.message
            });
        }
    }

    async updatePassword(req, res) {
        try {
            const user_id = req.user.id;
            console.log(user_id);
            const { password } = req.body;
            if (!password) {
                return res.status(400).json({
                    message: 'Password is required'
                });
            }
            const userdata = await User.findOne({ _id: user_id });
            console.log("userdata", userdata);
            if (userdata) {
                const newPassword = await hashePassword(password);
                const updateuser = await User.findOneAndUpdate({ _id: user_id },
                    {
                        $set: {
                            password: newPassword
                        }
                    });
                res.status(200).json({
                    message: 'Password updated successfully',
                    status: 200
                });
            } else {
                res.status(400).json({
                    message: 'password not updated'
                });
            }

        } catch (err) {
            console.log(err);
        }
    }

    async dashboard(req, res) {
        try {
            const { name, email, phone, role } = req.user;

            if (role !== "admin") {
                return res.status(403).json({
                    message: "Access Denied: Only admins can access this page",
                });
            }

            return res.status(200).json({
                message: "Welcome to the Dashboard, " + name,
                user: {
                    name,
                    email,
                    phone,
                    role,
                },
            });
        } catch (error) {
            return res.status(500).json({
                message: "Server Error",
                error: error.message,
            });
        }
    };

    async forgetPassword(req, res) {
        try {
            const { email } = req.body;
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRECT, { expiresIn: "1h" });
            const link = `http://localhost:5173/reset-password/${token}`;
            const mailOptions = {
                to: email,
                subject: "Password Reset",
                html: `<p>Hello ${user.name},</p>
                <p>Click the link below to reset your password:</p>
                <a href="${link}" style="display: inline-block; padding: 10px 20px; background-color: #007BFF; color: #fff; text-decoration: none; border-radius: 5px;">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request a password reset, please ignore this email.</p>
                <p>Thank you!</p>
                <p>Best regards,</p>
                <p>Team XYZ</p>
                <p><small>This is an automatically generated email. Please do not reply to this email.</small></p>
                <p><small>© 2025 Team Papai. All rights reserved.</small></p>
                <p><small>Powered by Papai</small></p>
                <p><small>Version 1.0</small></p>`,
            };
            await transporter.sendMail(mailOptions);
            return res.status(200).json({ message: "Email sent successfully, Check mail to change your password" });
        } catch (error) {
            return res.status(500).json({ message: "Server Error", error: error.message });
        }
    };

    async resetPassword(req, res) {
        try {
            const { token } = req.params;
            const { password, confirmPassword } = req.body;
            if (password !== confirmPassword) {
                return res.status(400).json({ message: "Passwords do not match" });
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRECT);
            const user = await User.findOne({ _id: decoded.id });
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
            await user.save();
            return res.status(200).json({ message: "Password reset successfully" });
        } catch (error) {
            return res.status(500).json({ message: "Server Error", error: error.message });
        }
    };

    async userProfile(req, res) {
        try {
            const user = req.user;
            return res.status(200).json({ user });
        } catch (error) {
            return res.status(500).json({ message: "Server Error", error: error.message });
        }
    };

}

module.exports = new AuthController();
