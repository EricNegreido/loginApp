import express from 'express'
import session from 'express-session'
import MongoStore from 'connect-mongo';
import __dirname from './utils.js';
import mongoose from 'mongoose';
import handlebars from 'express-handlebars'
import viewsRouter from './routes/views.router.js';
import sessionsRouter from './routes/sessions.router.js';
import cartsRouter from './routes/carts.router.js';
import productsRouter from './routes/products.router.js';
import intializePassport from './config/passport.config.js';
import passport from 'passport';




const app = express();

try {
    await mongoose.connect('mongodb+srv://ericnegreidooo:NwhiTotw0VIjgLVp@cluster47300ap.yetvntr.mongodb.net/sessionAndStorage?retryWrites=true&w=majority');
    console.log('BBd connected');
} catch (error) {
    console.log(error.message);
    
}

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(`${__dirname}/public`));



app.engine('handlebars', handlebars.engine());
app.set('views', `${__dirname}/views`);
app.set('view engine', 'handlebars');


app.use(session({
    store: MongoStore.create({
        client:mongoose.connection.getClient(),
        ttl: 60
        
    }),
    secret: 'Coder47300Secret',
    resave: true,
    saveUninitialized: true
}));
intializePassport();
app.use(passport.initialize());
app.use(passport.session());

app.use('/', viewsRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/carts', cartsRouter);
app.use('/api/products', productsRouter);

app.listen(8080, () => console.log('server running'));