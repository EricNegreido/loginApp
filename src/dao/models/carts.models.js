import mongoose from "mongoose";
import mongoosePaginate from 'mongoose-paginate-v2'


const cartsCollection = 'carts';

const cartsSchema = new mongoose.Schema({
    
    products:{
        type: [
            {
                product: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'products'
                }
            }
        ],
        default: []
    }

});
cartsSchema.plugin(mongoosePaginate);


export const cartsModel = mongoose.model(cartsCollection, cartsSchema); 