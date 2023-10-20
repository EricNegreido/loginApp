import {cartsModel} from '../models/carts.models.js';

export default class Carts {
    constructor(){
        console.log("Working carts with DB");
    }

    getArray= async (cid) => {
        const carts = await cartsModel.findById({_id: cid}).lean().populate('products.product'); // Con .lean() convertimos a un objetos manipulable en java
        return carts;

    }
    save = async (cart) => {
        const result = await cartsModel.create(cart);
        return result;
    }

    update = async (id, products) => {
        const result = await cartsModel.updateOne({_id: id}, products);
        return result
    }
    
}



