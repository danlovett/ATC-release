function initPassport(passport, LocalStrategy, clientDB, bcrypt) {
    passport.use(new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
        clientDB.get('SELECT * FROM users WHERE username = ?', username, async (err, user) => {
            if (!user) return done(null, false, { message: 'Incorrect username. Try again' })
            if(user == null) {
                console.log('got user!');
                return done(null, false);
            } 
            try {
                if(await bcrypt.compare(password, user.password)) {
                    return done(null, user)
                } else {
                    return done(null, false, { message: 'Incorrect password. Try again' })
                }
            } catch (err) { return done(null, false, { message: 'An error occured whilst accessing the database. Try again later.'}) }
        });
    }))
    
    passport.serializeUser((user, done) => {
        return done(null, user)
    })
    
    passport.deserializeUser((user, done) => {
        clientDB.get('SELECT * FROM users WHERE id = ?', user.id, (err, user) => {
            if (!user) return done(null, false);
            return done(null, user);
        });
    })
}

module.exports = initPassport

