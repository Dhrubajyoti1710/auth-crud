const mongoose=require('mongoose');

const Schema= mongoose.Schema

const UserSchema=new Schema({
    name: {
        type: String,
        required: [true, 'Please add a name']
    },
    email: {
        type: String,
        required: [true, 'Please add an email'],
    },
    phone: {
        type: String,
        required: [true, 'Please add a phone number']
    },
    password: {
        type: String,
        required: [true, 'Please add a password']
    },
    role: {
        type: String,
        default: 'user'
    },
    is_verified: { type: Boolean, default: false },
},{
    timestamps: true,
})

const UserModel=mongoose.model('User',UserSchema)
module.exports=UserModel