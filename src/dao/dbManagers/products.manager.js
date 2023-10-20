import {productsModel} from '../models/products.models.js';

export default class Products {
    constructor(){
        console.log("Working products with DB");
    }

    getAll = async (limit, page, sort, query) => {
        // const products = await productsModel.find().lean(); // Con .lean() convertimos a un objetos manipulable en java
        const filtro = query ? {title: query} : {}; 
        const products = await productsModel.paginate(filtro, { sort: {price : sort}, limit: limit, page: page});

        return products;

    }
    getById = async (id) => {
        const product = await productsModel.findById({_id: id}).lean(); // Con .lean() convertimos a un objetos manipulable en java
        return product;

    }
    save = async (product) => {
        const result = await productsModel.create(product);
        return result;
    }

    update = async (id, product) => {
        const result = await productsModel.updateOne({_id: id}, product);
        return result
    }
}



