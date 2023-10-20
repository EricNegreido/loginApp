import mongoose from "mongoose";
import mongoosePaginate from 'mongoose-paginate-v2'


const productsCollection = 'products';

const productsSchema = new mongoose.Schema({
    title:{
        type: String,
        require: true
    },
    description:{
        type: String,
        require: true
    },
    price:{
        type: Number,
        require: true
    },
    stock:{
        type: Number,
        require: true
    }

});
productsSchema.plugin(mongoosePaginate);

export const productsModel = mongoose.model(productsCollection, productsSchema); 



