# Restocat Passport

## Installation


`npm i restocat-passport`


## How to use

```javascript

    // passport init and register strategies
    const passport = require('restocat-passport');
    const LocalStrategy = require('passport-local').Strategy;
    const ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
    const BasicStrategy = require('passport-http').BasicStrategy;
    const BearerStrategy = require('passport-http-bearer').Strategy;

    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser((id, done) => mongoose.model('User').findById(id, done));

    passport.use(new LocalStrategy({passReqToCallback: true}, /* handler */));
    passport.use(new BasicStrategy({passReqToCallback: true}, /* handler */));
    passport.use(new BearerStrategy(/* handler */));
    passport.use(new ClientPasswordStrategy({passReqToCallback: true}, /* handler */));

    const clientAuth = passport.authenticate(['basic', 'oauth2-client-password'], {failWithError: true});
    const userAuth = passport.authenticate('bearer', {failWithError: true});

    // and somewhere

    const {user, authInfo, status} = await userAuth(this.$context);
```