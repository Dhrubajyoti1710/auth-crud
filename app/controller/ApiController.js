
const Product = require('../model/product')
const path = require('path')
const fs = require('fs')

class ApiController {
  async createProduct(req, res) {
    //console.log(req.body);
    try {
      const { name, price, size, color, brand, description } = req.body

      const addData = await Product({
        name, price, size, color, brand, description
      })
      if (req.file) {
        addData.image = req.file.path
      }
      const result = await addData.save()
      return res.status(201).json({
        message: "Product added successfully",
        data: result
      })
    } catch (error) {
      return res.status(500).json({
        message: error.message
      })
    }
  }

  async showProduct(req, res) {
    //console.log(req.body);
    try {
      const showData = await Product.find()
      if (req.file) {
        showData.image = req.file.path
      }
      return res.status(201).json({
        message: "Products fetched successfully",
        total: showData.length,
        data: showData
      })

    } catch (error) {
      return res.status(500).json({
        message: error.message
      })
    }
  }

  async findProduct(req, res) {
    //console.log(req.body);
    try {
      const id = req.params.id
      const edit = await Product.findById(id)
      if (req.file) {
        edit.image = req.file.path
      }
      return res.status(200).json({
        message: "Product found successfully",
        data: edit
      })

    } catch (error) {
      return res.status(500).json({
        message: error.message
      })
    }
  }
  async updateProduct(req, res) {
    try {
      const id = req.params.id;
      const { name, price, size, color, brand, description } = req.body;

      const update = await Product.findByIdAndUpdate(
        id,
        { name, price, size, color, brand, description },
        { new: true }
      );

      if (!update) {
        return res.status(404).json({ message: "Product not found" });
      }
      if (req.file) {
        update.image = req.file.path;
        await update.save();
      }

      return res.status(200).json({
        message: "Product updated successfully",
        product: update,
      });

    } catch (error) {
      return res.status(500).json({
        message: error.message
      });
    }
  }

  async deleteProduct(req, res) {
    try {
      const id = req.params.id;

      const product = await Product.findById(id);

      if (product.image) {
        const imagePath = path.join(__dirname, '../../', product.image);
        fs.unlink(imagePath, (err) => {
          if (err) console.error("Error deleting image:", err);
        });
      }
      await Product.findByIdAndDelete(id);

      return res.status(200).json({
        message: "Product deleted successfully",
      });

    } catch (error) {
      return res.status(500).json({
        message: error.message
      });
    }
  }


  async filterProducts(req, res) {
    try {
        const { size, color, brand } = req.query;
        const query = {};
        if (size) query.size = { $in: size.split(",") };
        if (color) query.color = { $in: color.split(",") };
        if (brand) query.brand = { $in: brand.split(",") };

        const filteredProducts = await Product.find(query);

        return res.status(200).json({
            message: "Data fetched successfully",
            totalCount: filteredProducts.length,
            data: filteredProducts,
        });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}



  

}

module.exports = new ApiController()