const mongoose = require('mongoose')

const Schema = mongoose.Schema

const ProductSchema = new Schema({
    name: {
        type: String,
        required: [true, "name is required"]

    },
    price: {
        type: Number,
        required: [true, "Price is required"]
    },
    size: {
        type: [String],
        required: [true, "size is required"],
    },
    color: {
        type: [String],
        required: [true, "color is required"],
    },
    brand: {
        type: String,
        required: [true, "brand is required"],
    },
    
    description: {
        type: String,
        required: [true, "Description is required"]
    },
    image: {
        type: String,
        // required: [true, "Image is required"]
    }
}, { timestamps: true })

const ProductModel = mongoose.model('product', ProductSchema)
module.exports = ProductModel