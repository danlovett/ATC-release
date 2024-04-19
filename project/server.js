const express = require('express');
const app = express();
const favicon = require('serve-favicon')

const sqlite3 = require('sqlite3');
const clientDB = new sqlite3.Database('./db/data.db', sqlite3.OPEN_READWRITE, err => { if(err) throw err })
const gameDB = new sqlite3.Database('./db/game.db', sqlite3.OPEN_READWRITE, err => { if(err) throw err })

const CryptoJS = require('crypto-js');
const bcrypt = require('bcrypt')

const fs = require('fs'); 

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const flash = require('express-flash')
const session = require('express-session')

const initPassport = require('./passport-config');
initPassport(passport, LocalStrategy, clientDB, bcrypt, fs)

app.use(favicon('./images/icon.png'));

app.use(express.static(__dirname))
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
    secret: `${Math.random().toString()}`,
    resave: false,
    cookie: { maxAge: 1000 * 60 * 60 * 12},
    saveUninitialized: false
}));

app.use(passport.initialize())
app.use(passport.session())

app.engine('html', require('ejs').renderFile);

app.set('view engine', 'ejs');

app.get('/test', checkAuthenticated, (req, res) => {
    res.render('private/admin/test.ejs')
})

app.get('/', checkNotAuthenticated, (req, res) => {
    res.render('public/home.ejs')
})

app.get('/login', checkNotAuthenticated, (req, res, next) => {
    res.render('public/login');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
        successRedirect: '/login-success/log',
        failureRedirect: `/login`,
        failureFlash: true
}));

app.get('/signup', checkNotAuthenticated, (req, res) => {
    res.render('public/signup', { message: req.query.message });
});

app.post('/signup', checkNotAuthenticated, async (req,res) => {
    if(req.body.password.length < 8) {
        res.redirect('/signup')
        return
    } 
    if(!req.body.name.includes(' ')) {
        res.redirect('/signup?message=full_name')
        return
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const sql = `INSERT INTO users(name, username, password) VALUES ("${req.body.name}", "${req.body.email}", "${hashedPassword}")`
    clientDB.all(sql, [], err => { 
        if(err) {
            if(err.errno == 19) res.redirect('/login?message=aid') 
        }
        if(req.body.password.length >= 8 && req.body.name.includes(' ') && !err) res.redirect('/login')
    })
})

//PRIVATE
app.get('/home', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    gameDB.all('SELECT image_reference, airport_name, airport_icao FROM levels', [], (err, levels) => {
        if(err) add_user_log('ACCESS', err)
        clientDB.all(`SELECT name, date, score, level, personID FROM leaderboard ORDER BY score DESC LIMIT 3;`, [], (err, leaderboard) => {
            if(err) add_user_log('ACCESS', err)
            clientDB.all(`SELECT users.name, users.username, users.pfp, users.last_played FROM users LEFT JOIN friends ON users.id = friends.passive_user WHERE friends.lead_user = ? AND friends.status = ?`, [req.user.id, "Active"], (err, following) => { // change 30 to current user
                if(err) add_user_log('ACCESS', err)
                res.render('private/home.ejs', { levels: levels, leaderboard: leaderboard, following: following });
            })
        })
    })
})

app.get('/leaderboard', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    clientDB.all(`SELECT name, date, score, level, personID FROM leaderboard ORDER BY score DESC;`, [], (err, leaderboard) => {
        if(err) add_user_log('ACCESS', err)
        res.render('private/leaderboard.ejs', { leaderboard: leaderboard });
    })
})

app.get('/settings/:page', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    if(req.params.page == 'home') {
        res.render('private/settings/settings.ejs', { is_admin: req.user.is_admin } )
    } else if(req.params.page == 'profile') {
        clientDB.get(`SELECT id, name, username, pfp FROM users WHERE id = ${req.user.id}`,(err, user) => {
            if(err) add_user_log('ACCESS', err)
            clientDB.all(`SELECT score, level, date FROM leaderboard WHERE personID = ${req.user.id}`, [], (err, leaderboard) => {
                if(err) add_user_log('ACCESS', err)
                clientDB.all(`SELECT friends.lead_user, friends.status, friends.creation_date, users.id, users.username, users.name, users.pfp FROM users LEFT JOIN friends ON users.id = friends.lead_user WHERE friends.passive_user = ? AND friends.status = ?`, [req.user.id, "Active"], (err, followers) => {
                    if(err) add_user_log('ACCESS', err)
                    clientDB.all(`SELECT history.level, history.date, history.score FROM history LEFT JOIN users ON history.personID = users.id WHERE users.id = ${req.user.id} ORDER BY history.date DESC`, [], (err, history) => {
                        if(err) add_user_log('ACCESS', err)
                        res.render('private/settings/profile', { user: user, history: history, leaderboard: leaderboard, followers: followers, current_user: req.user.id, is_admin: req.user.is_admin })
                    })
                })
            })
        })
    } else if(req.params.page == 'friends') {
        clientDB.all(`SELECT users.id, users.name, users.username, users.pfp, users.last_played, friends.creation_date FROM users LEFT JOIN friends ON users.id = friends.passive_user WHERE friends.lead_user = ? AND friends.status = ?`, [req.user.id, "Requested"], (err, requested_followers) => {
            if(err) add_user_log('ACCESS', err)
            clientDB.all(`SELECT users.id, users.name, users.username, users.pfp, users.last_played, friends.creation_date FROM users LEFT JOIN friends ON users.id = friends.lead_user WHERE friends.passive_user = ? AND friends.status = ?`, [req.user.id, "Requested"], (err, follower_requests) => {
                if(err) add_user_log('ACCESS', err)
                clientDB.all(`SELECT users.id, users.name, users.username, users.pfp, users.last_played, friends.creation_date FROM users LEFT JOIN friends ON users.id = friends.passive_user WHERE friends.lead_user = ? AND friends.status = ?`, [req.user.id, "Active"], (err, following) => {
                    if(err) add_user_log('ACCESS', err)
                    clientDB.all(`SELECT users.id, users.name, users.username, users.pfp, users.last_played, friends.creation_date FROM users LEFT JOIN friends ON users.id = friends.lead_user WHERE friends.passive_user = ? AND friends.status = ?`, [req.user.id, "Active"], (err, followers) => {
                        if(err) add_user_log('ACCESS', err)
                        res.render('private/settings/friends.ejs', { requested_followers: requested_followers, follower_requests: follower_requests, following: following, followers: followers, is_admin: req.user.is_admin })
                    })
                })
            })
        })
    } else if(req.params.page == 'general') {
        clientDB.get(`SELECT id, name, username, pfp FROM users WHERE id = ${req.user.id}`,(err, user) => {
            if(err) add_user_log('PFP', err)
            res.render('private/settings/general.ejs', { is_admin: req.user.is_admin, user: user, success: req.params.bool })
        })
    } else if(req.params.page == 'admin') {
        clientDB.all('SELECT * FROM logs WHERE type == "ACCESS"', [], (err, user_access_logs) => {
            clientDB.all('SELECT * FROM logs WHERE type == "LOGIN" OR type == "LOGOUT"', [], (err, user_auth_logs) => {
                gameDB.all('SELECT id, airport_icao FROM levels', [], (err, levels) => {
                    clientDB.all('SELECT * FROM users', [], (err, users) => {
                        console.log(levels)
                        res.render('private/settings/admin.ejs', { user_auth_logs: user_auth_logs, user_access_logs: user_access_logs, levels: levels, all_users: users, is_admin: req.user.is_admin })
                    })
                })
            })
        })
    } else {
        res.redirect('/error/settings')
    }
})

app.get('/settings/admin/p/:id', checkAuthenticated, (req, res) => {
    clientDB.all('SELECT * FROM leaderboard WHERE personID = ?', req.params.id, (err, leaderboard) => {
        if(err) user_access_logs('ACCESS', err)
        clientDB.all('SELECT id, pfp, name, username, last_played, best_played, points, creation_date, is_admin FROM users WHERE id = ?', req.params.id, (err, user) => {
            if(err) user_access_logs('ACCESS', err)
            clientDB.all('SELECT * FROM history WHERE personID = ?', req.params.id, (err, history) => {
                if(err) user_access_logs('ACCESS', err)
                res.render('private/settings/manage_profile.ejs', { user: user, leaderboard: leaderboard, history: history, is_admin: req.user.is_admin })
            })
        })
    })
})

app.post('/edit_picture', checkAuthenticated, (req, res) => {
    if(isImage(req.body.url)) {
        clientDB.run(`UPDATE users SET pfp = '${req.body.url}' WHERE id = ${req.user.id}`, [], err => {
            if(!err) res.redirect('/settings/general')
        })
    } else {
        res.redirect('/settings/general')
    }
})

app.post('/edit_level_image/:id', checkAuthenticated, (req, res) => {
    if(isImage(req.body.url)) {
        gameDB.run(`UPDATE levels SET image_reference = '${req.body.url}' WHERE id = ${req.params.id}`, [], err => {
            if(!err) res.redirect(`/admin/edit/${req.params.id}/details`)
        })
    } else {
        console.log(err)
        res.redirect('/home')
    }
})

app.post('/edit_level_icao/:id', checkAuthenticated, (req, res) => {
    gameDB.run(`UPDATE levels SET airport_icao = '${req.body.airport_icao}' WHERE id = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/admin/edit/${req.params.id}/details`)
    })
})

app.post('/edit_level_name/:id', checkAuthenticated, (req, res) => {
    gameDB.run(`UPDATE levels SET airport_name = '${req.body.airport_name}' WHERE id = ${req.params.id}`, [], err => {
        console.log(req.body.airport_name, req.params.id)
        if(!err) res.redirect(`/admin/edit/${req.params.id}/details`)
    })
})

app.post('/edit_level_waffle/:id', checkAuthenticated, (req, res) => {
    gameDB.run(`UPDATE levels SET airport_name = '${req.body.waffle}' WHERE id = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/admin/edit/${req.params.id}/details`)
    })
})

app.post('/edit_level_mission/:id', checkAuthenticated, (req, res) => {
    gameDB.run(`UPDATE levels SET airport_name = '${req.body.mission}' WHERE id = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/admin/edit/${req.params.id}/details`)
    })
})

app.post('/search', checkAuthenticated, (req, res) => {
    if(req.body.query.includes('?') || req.body.query.includes('=')) {
        res.redirect('/search')
    } else { 
        let words
        try { words = req.body.query.split(' ') } catch { words = req.body.query }
        if(words != '') {
            for (let i = 0; i < words.length; i++) {
                words[i] = words[i][0].toUpperCase() + words[i].substr(1);
            }
        }
        res.redirect(`/search?query=${words.toString().replace(',', ' ')}`)
    }
})

app.get('/search', checkAuthenticated, (req, res) => {
    if(req.query.query != undefined) {
        gameDB.all(`SELECT airport_name, airport_icao, image_reference FROM levels WHERE airport_name LIKE '%${req.query.query}%'`, [], (err, levels) => {
            if(err) add_game_log('ACCESS', err)
            clientDB.all(`SELECT users.id, users.pfp, users.name, users.username, friends.passive_user, friends.lead_user, friends.creation_date, friends.status FROM users LEFT JOIN friends ON friends.passive_user = users.id WHERE name LIKE '%${req.query.query}%'`, [], (err, users) => {
                if(err) add_user_log('ACCESS', err)
                // ERROR -FIX
                // multiple entries will show when user has multiple friend requests
                res.render('private/search.ejs', { query: req.query.query, levels: levels, users: users, current_user: req.user.id })
            })
        })
    } else {
        res.render('private/search.ejs', { query: 'none', levels: undefined, users: undefined })
    }
})

app.get('/profile/:id', checkAuthenticated, (req, res) => {
    if(req.params.id == req.user.id) res.redirect('/settings/profile')
    clientDB.get(`SELECT id, name, username, pfp FROM users WHERE id = ${req.params.id}`,(err, user) => {
        if(err) add_user_log('ACCESS', err)
        clientDB.all(`SELECT score, level, date FROM leaderboard WHERE personID = ${req.params.id}`, [], (err, leaderboard) => {
            if(err) add_user_log('ACCESS', err)
            clientDB.all(`SELECT friends.lead_user, friends.status, friends.creation_date, users.username, users.name, users.pfp FROM users LEFT JOIN friends ON users.id = friends.lead_user WHERE friends.passive_user = ? AND friends.status = ?`, [req.params.id, "Active"], (err, followers) => {
                if(err) add_user_log('ACCESS', err)
                clientDB.all(`SELECT history.level, history.date, history.score FROM history LEFT JOIN users ON history.personID = users.id WHERE users.id = ${req.params.id} ORDER BY history.date DESC`, [], (err, history) => {
                    if(err) add_user_log('ACCESS', err)
                    res.render('private/profile', { user: user, history: history, leaderboard: leaderboard, followers: followers, current_user: req.user.id })
                })
            })
        })
    })
})

app.get('/play/:id', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    gameDB.get(`SELECT * from levels WHERE airport_icao = "${req.params.id}";`, [], (err, level) => {
        if(err) add_game_log('ACCESS', err)
        gameDB.all('SELECT * from airlines LEFT JOIN airframes ON airlines.airframe = airframes.id;', [], (err, plane_data) => {
            if(err) add_game_log('ACCESS', err)
            res.render('private/play.ejs', { data: level, plane_data: plane_data });
        })
    })
})

app.get('/levels', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    gameDB.all('SELECT airport_name, airport_icao, text_waffle, text_instructions, image_reference, author FROM levels', [], (err, levels) => {
        if(err) add_game_log('ACCESS', err)
        res.render('private/levels.ejs', { levels: levels })
    })
})

app.get('/play-ended', checkAuthenticated, (req,res) => {
    clientDB.get('SELECT points FROM users WHERE id = ?', req.user.id, (err, row) => {
        if(err) add_user_log('ACCESS', err)
        clientDB.all('UPDATE users SET points = ? WHERE id = ?', parseInt(row.points) + parseInt(req.query.score), req.user.id, err => { if(err) add_user_log('ACCESS', err) }) 
    })

    clientDB.get(`SELECT * FROM history WHERE personID = ${req.user.id} ORDER BY score DESC;`, [], (err, row) => {
        if(err) add_user_log('ACCESS', err)
        clientDB.all(`UPDATE users SET best_played = '${row.level}' WHERE id = ${req.user.id}`, [], (err) => { if(err) add_user_log('ACCESS', err) }) // undefined FIX THIS
    })

    clientDB.all(`UPDATE users SET last_played = '${req.query.level}' WHERE id = ${req.user.id}`, [], (err) => { if(err) add_user_log('ACCESS', err) }) // undefined FIX THIS
    clientDB.all(`INSERT INTO history (date, score, level, personID) VALUES('${formatTime()}', ${req.query.score}, '${req.query.level}', ${req.user.id});`, [], err => { if(err) add_user_log('ACCESS', err) })
    clientDB.all('DELETE FROM leaderboard WHERE personID = ?', req.user.id, err => { if(err) add_user_log('ACCESS', err) })
    clientDB.all(`INSERT INTO leaderboard(name, date, score, level, personID) VALUES('${req.user.name}', '${formatTime()}', ${req.query.score}, '${req.query.level}', ${req.user.id});`, [], err => { if(err) add_user_log('ACCESS', err)})

    gameDB.all('SELECT image_reference FROM levels WHERE airport_name=?', req.query.level, (err, image) => {
        if(err) add_game_log('ACCESS', err)
        res.render('private/terminate_play.ejs', { level: req.query.level, image: image, score: req.query.score, time: req.query.time, reason: req.query.reason })
    })
})

// friend stuff
app.get('/add_friend/:id', checkAuthenticated, (req, res) => {
    clientDB.all('INSERT INTO friends(lead_user, passive_user, creation_date, status) VALUES(?, ?, DATETIME("now"), "Requested")', [req.user.id, req.params.id], err => { 
        if(err) add_user_log('ACCESS', err)
        res.redirect('/settings/friends')
    })
})

app.get('/accept_request/:id', checkAuthenticated, (req, res) => {
    clientDB.all('UPDATE friends SET status = ? WHERE passive_user = ? AND lead_user = ?', ['Active', req.user.id, req.params.id], (err) => {
        if(err) add_user_log('ACCESS', err)
        res.redirect('/settings/friends')
    })
})

app.get('/remove_request/:id', checkAuthenticated, (req, res) => {
    clientDB.all('DELETE FROM friends WHERE lead_user = ? AND passive_user = ?', [req.user.id, req.params.id], err => { 
        if(err) add_user_log('ACCESS', err)
        res.redirect('/settings/friends')
     })
})

app.get('/remove_friend/:id', checkAuthenticated, (req, res) => {
    clientDB.all('DELETE FROM friends WHERE lead_user = ? AND passive_user = ?', [req.user.id, req.params.id], err => { 
        if(err) add_user_log('ACCESS', err)
        res.redirect('/settings/friends')
    })
})

app.get('/reject_friend/:id', checkAuthenticated, (req, res) => {
    clientDB.all('DELETE FROM friends WHERE lead_user = ? AND passive_user = ?', [req.params.id, req.user.id], err => {
        if(err) add_user_log('ACCESS', err)
        res.redirect('/settings/friends')
    })
})

app.get('/logout', (req, res, next) => {
    let id = req.user.id
    req.logout((err) => {
        if (err) { return next(err) }
        add_user_log('LOGOUT', `${id}`)
        res.redirect('/login');
    });
})

app.get('/login-success/log', checkAuthenticated, (req, res) => {
    add_user_log('LOGIN', `${req.user.id}`)
    res.redirect('/home')
})

app.get('/error/:message', (req, res) => {
    res.render('private/error.ejs', { message: req.params.message})
})




app.get('/admin/edit/:id/:page', checkAuthenticated, (req, res) => {
    if(req.params.page == "details") {
        gameDB.all('SELECT * FROM levels WHERE id = ?', [req.params.id], (err, level) => {
            res.render('private/admin/edit.ejs', {level: level})
        })
    }
    if(req.params.page == "layout") {
        gameDB.all('SELECT * FROM levels WHERE id = ?', [req.params.id], (err, level) => {
            res.render('private/admin/layout.ejs', {level: level})
        })
    }
})

app.get('/create_layout', checkAuthenticated, (req, res) => {
    res.render('private/admin/createLayout.ejs')
})

app.post('/finish_creation', checkAuthenticated, (req, res) => {
    console.log(req.body.data)
    res.render('private/admin/finished', {data: req.body.data})
})

app.get('/:option/confirm/:id', checkAuthenticated, (req, res) => {
    if(req.params.option == "logout") res.render('private/settings/confirm.ejs', {message: "logout", is_admin: undefined})
    if(req.params.option == "delete_user") res.render('private/settings/confirm.ejs', {message: "delete_user", is_admin: req.user.is_admin, user_to_delete: req.params.id})
    if(req.params.option == "make_admin") res.render('private/settings/confirm.ejs', {message: "make_admin", is_admin: req.user.is_admin, make_admin_user: req.params.id})
})

app.get('/make_admin/:id', checkAuthenticated, (req, res) => {
    clientDB.run(`UPDATE users SET is_admin = "true" WHERE id = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/settings/admin/p/${req.params.id}`)
    })
})

app.get('/remove_admin/:id', checkAuthenticated, (req, res) => {
    clientDB.run(`UPDATE users SET is_admin = "false" WHERE id = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/settings/admin/p/${req.params.id}`)
    })
})

app.get('/delete_user/:id', checkAuthenticated, (req, res) => {
    clientDB.run(`DELETE FROM users WHERE id = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/settings/admin`)
        if(err) console.log(err)
    })
})

app.get('/remove/history/:id/:returnId', checkAuthenticated, (req, res) => {
    clientDB.all('DELETE FROM history WHERE id = ?', [req.params.id], err => {
        if(err) add_user_log('REMOVE_HISTORY', err)
        res.redirect(`/settings/admin/p/${req.params.returnId}`)
    })
})

app.get('/remove_history/:id', checkAuthenticated, (req, res) => {
    clientDB.run(`DELETE FROM history WHERE personId = ${req.params.id}`, [], err => {
        if(!err) res.redirect(`/settings/admin`)
        if(err) console.log(err)
    })
})



// Get date now and format it to custom
function formatTime() {
    const date = new Date();
    const day = `${date.getFullYear()}-${date.getMonth()}-${date.getDay()}`
    const hours = date.getHours()
    const mins = `${date.getMinutes()<10?'0':''}${date.getMinutes()}`
    return `${day} ${hours}:${mins}`
}

// checking if current session is active
function checkAuthenticated(req, res, next) {
    if(req.isAuthenticated()) { return next() }
    res.redirect(`/login`)
}

// checking if theres a session
function checkNotAuthenticated(req, res, next) {
    if(req.isAuthenticated()) { return res.redirect('/home') }
    next()
}

function add_game_log(type, log) {
    gameDB.all('INSERT INTO logs(date, type, description) VALUES(DATETIME("now"), ?, ?)', [type, log], err => { if(err) throw err })
}

function add_user_log(type, log) {
    clientDB.all('INSERT INTO logs(date, type, description) VALUES(DATETIME("now"), ?, ?)', [type, log], err => { if(err) throw err })
}

function isImage(url) {
    return /\.(jpg|jpeg|png|webp|avif|gif|svg)$/.test(url);
}

app.listen(4000);