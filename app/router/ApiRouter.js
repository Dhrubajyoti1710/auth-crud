const express=require('express')
const ApiController = require('../controller/ApiController')
const productImageUpload = require('../helper/productImage')
const { AuthCheck } = require('../middleware/Auth')
const router=express.Router()

//for api Route
router.post('/product/create',AuthCheck,productImageUpload.single('image'),ApiController.createProduct)
router.get('/product/filter', ApiController.filterProducts);
router.get('/product',AuthCheck,ApiController.showProduct)
router.get('/product/:id',AuthCheck,ApiController.findProduct)
router.post('/product/update/:id',AuthCheck,productImageUpload.single('image'),ApiController.updateProduct)
router.delete('/product/delete/:id',AuthCheck,ApiController.deleteProduct)



module.exports=router