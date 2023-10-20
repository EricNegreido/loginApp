// Rutas que se renderizan !!!!

import { Router } from "express";
import Products from '../dao/dbManagers/products.manager.js'
import Carts from '../dao/dbManagers/carts.manager.js'

const productsManager = new Products();

const cartsManager = new Carts();

const router = Router();

const publicAccess = (req, res, next) =>{
    if(req.session.user) return res.redirect('/');
    next();
}

const privateAccess = (req, res, next) => {

    if(!req.session.user) return res.redirect('/login');
    next();

}

router.get('/register', publicAccess, (req, res) => {
    res.render('register');
});


router.get('/login', publicAccess, (req, res) => {
    res.render('login');
});

router.get('/', privateAccess, (req, res) => {
    res.render('profile', {
        user: req.session.user
    });
});

router.get('/products', async (req, res) =>{
    const {page = 1 , limit = 5, sort, query} = req.query;
    try{
        const {docs, hasPrevPage, hasNextPage, nextPage, prevPage} = await productsManager.getAll(limit, page, sort, query);
        const product = docs;
        console.log(docs);
       
        res.render('products', {
            product,
            hasPrevPage,
            hasNextPage,
            nextPage,
            prevPage,
            user: req.session.user


        }) //renderizo views
    }catch(error){
        console.log(error.message);
        res.status(500).send('ERROR AL CARGAR VIEWS')
    }
});

router.get('/carts/:cid', async (req, res) =>{

    const {cid} = req.params;
    try{
        const carts = await cartsManager.getArray(cid);
        res.send({status: 'sucess', payload: carts});
    }catch(error){
        console.log(error.message);
    }
});
 
export default router;