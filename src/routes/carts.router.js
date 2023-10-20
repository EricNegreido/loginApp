import { Router } from "express";
import Carts from '../dao/dbManagers/carts.manager.js';
import Products from '../dao/dbManagers/products.manager.js';


const router = Router();
const cartsManager = new Carts();
const productsManager = new Products();


router.get('/:cid', async (req, res) =>{

    const {cid} = req.params;
    try{
        const carts = await cartsManager.getArray(cid);
        res.send({status: 'sucess', payload: carts});
    }catch(error){
        res.status(500).send({status: 'error', error: error.message})
    }

});

router.post('/', async (req, res) =>{
    
    try{
        const result = await cartsManager.save();
        res.status(201).send({status: 'sucess', payload: result}); 

    }catch(error){
        res.status(500).send({status: 'error', error: error.message})
    }
});

router.post("/:cid/products/:pid", async (req, res) => {
    try {
        const cid = req.params.cid;
        const pid = req.params.pid;
        const { quantity } = req.body;

        const cart = await cartsManager.getArray(cid)
        const product = await productsManager.getById(pid);

        if(cart){


            if (product) {
                const existingProduct = cart.products.find(item => item.id === pid);
                if (existingProduct) {

                    existingProduct.quantity += quantity || 1;
                } else {

                    cart.products.push({ product: pid, quantity: quantity || 1 });
                }
        }

     }


    const result = await cartsManager.update(cid, { products: cart.products });
    console.log(result)
    res.status(201).send({status: 'sucess', payload: result}); 


    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'ERROR AL AGREGAR EL PRODUCTO' });
    }
});


router.put("/:cid/products/:pid", async (req, res) => {
    try {
        const cid = req.params.cid;
        const pid = req.params.pid;
        const { quantity } = req.body;

        const cart = await cartsManager.getArray(cid)
        const product = await productsManager.getById(pid);

        if(cart && product){

            const existingProduct = cart.products.find(item => item.id === pid);
            if (existingProduct) {

                existingProduct.quantity += quantity || 1;
            }

     }


    const result = await cartsManager.update(cid, { products: cart.products });
    console.log(result)
    res.status(201).send({status: 'sucess', payload: result}); 


    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'ERROR AL AGREGAR EL PRODUCTO' });
    }
});

router.delete("/:cid/products/:pid", async (req, res) => {
    try {
        const cid = req.params.cid;
        const pid = req.params.pid;

        const cart = await cartsManager.getArray(cid)
        const product = await productsManager.getById(pid);

        if(cart && product){

            cart.products = cart.products.filter(item => item.id !== pid);
            const result = await cartsManager.update(cid, { products: cart.products });
            console.log(result)
            res.status(201).send({status: 'sucess', payload: result}); 
        }else{
            res.status(404).json({ error: 'NO SE ENCONTRO PRODUCTO O CARRITO' });
        }
        

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'ERROR AL ELIMINAR EL PRODUCTO' });
    }
});
router.delete("/:cid", async (req, res) => {
    try {
        const cid = req.params.cid;

        const cart = await cartsManager.getArray(cid)

        if(cart){

            cart.products = [];
            const result = await cartsManager.update(cid, { products: cart.products });
            console.log(result)
            res.status(201).send({status: 'sucess', payload: result}); 
        }else{
            res.status(404).json({ error: 'NO SE ENCONTRO PRODUCTO O CARRITO' });
        }
        

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'ERROR AL ELIMINAR EL PRODUCTO' });
    }
});

export default router;