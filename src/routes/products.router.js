import { Router } from "express";
import Products from '../dao/dbManagers/products.manager.js';

const router = Router();
const productsManager = new Products();


router.get('/', async (req, res) =>{

    const {page = 1 , limit = 5, sort, query} = req.query;
    try{
        const products = await productsManager.getAll(limit, page, sort, query);
        res.send({status: 'sucess', payload: products});
    }catch(error){
        res.status(500).send({status: 'error', error: error.message})
    }

});

router.get('/:id', async (req, res) =>{
    const {id} = req.params
    try{
        const products = await productsManager.getById(id);
        res.send({status: 'sucess', payload: products});
    }catch(error){
        res.status(500).send({status: 'error', error: error.message})
    }

});

router.post('/', async (req, res) =>{
    const {title, description, price, stock} = req.body
    
    if(!title || !description || !price || !stock){
        return res.status(400).send({status: 'error', error: 'incomplete values'}); 
    }
    try{
        const result = await productsManager.save({
            title,
            description,
            price,
            stock
        });
        res.status(201).send({status: 'sucess', payload: result}); 

    }catch(error){
        res.status(500).send({status: 'error', error: error.message})
    }
});

router.put('/:id', async (req, res) =>{
    const {title, description, price, stock} = req.body

    const {id} = req.params;
    if(!title || !description || !price || !stock){
        return res.status(400).send({status: 'error', error: 'incomplete values'}); 
    }
    
    try{
        const result = await productsManager.update(id, {
            title,
            description,
            price,
            stock
        });
        res.send({status: 'sucess', payload: result});


    }catch(error){
        res.status(500).send({status: 'error', error: error.message})
    }
});

export default router;