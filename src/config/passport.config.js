import passport from "passport";
import local from 'passport-local';
import GitHubStrategy from 'passport-github2'
import usersModel from "../dao/models/users.models.js";
 import {createHash, isValidPassword} from "../utils.js";


const LocalStrategy = local.Strategy;


const intializePassport = () => {

    passport.use('register', new LocalStrategy({
        passReqToCallback : true, //permite acceder al obj req
        usernameField: 'email' //por defecto espera recibir un user -> cambiamos por email

    }, async(req, username, password, done/* callback para retornar exito o error*/) =>{

        const email = username;
        try {
            const {first_name, last_name, age} = req.body;
            
            const exists = await usersModel.findOne({email});
            if(exists){
                return done(null, false);
                
            }
           
            const rol = (email === "adminCoder@coder.com" && password == "adminCod3r123" ) ? 'User' : 'Admin';
            const user = await usersModel.create({
                first_name,
                last_name, 
                email,
                age,
                password: createHash(password),
                rol: rol
    
            });
            return done(null, user);            
        } catch (error) {
            return done(`Error al registrar usuario, ${error.message}`);
    
        }
    }))



    passport.use('login', new LocalStrategy({
            usernameField: 'email'
        }, async(username, password, done) =>{

            try {
                const user = await usersModel.findOne({ email: username}); 
    
                if(!user){
                    console.log("user")
                    return done(null, false);
                }

                if(!isValidPassword(user, password)){
                    return done(null, false);
                }

                return done(null, user); // se setea en req.user
            } catch (error) {
                return done(`Error al loguear usuario, ${error.message}`);

            }
        }));
    passport.use('github', new GitHubStrategy({
        clientID: 'Iv1.8b57cd0a12625a16',
        clienteSecret: 'db846c8946f3ba43926f80b0f059e7b2dff449de',
        callbackURL: 'http://localhost:8080/api/sessions/github-callback',
        scope: ['user:email'],

    }, async(accessToken, refreshToken, profile, done) =>{
        try {
            console.log(profile);
            const email = profile.emails[0].value;
            const user = await usersModel.findOne(email);
            if(!user){
                const newUser ={
                    first_name: profile._json.name,
                    last_name: "",
                    age: 22,
                    email,
                    password:""
                };

                const result = await usersModel.create(newUser);
                return done(null, result);
            }else{
                return done(null, user);
            }
        } catch (error) {
            return done(error);           
        }
    }))

    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser( async (id, done) =>{
        const user = await usersModel.findById(id);
        done(null, user); 
    })

};

export default intializePassport;


