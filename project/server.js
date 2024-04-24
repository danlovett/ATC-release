const express = require('express');
const app = express();
const favicon = require('serve-favicon')

const sqlite3 = require('sqlite3');
const clientDB = new sqlite3.Database('./db/data.db', sqlite3.OPEN_READWRITE, err => { if(err) throw err })
const gameDB = new sqlite3.Database('./db/game.db', sqlite3.OPEN_READWRITE, err => { if(err) throw err })
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

app.get('/', checkNotAuthenticated, (req, res) => {
    res.render('public/home')
})

app.get('/login', checkNotAuthenticated, (req, res, next) => {
    res.render('public/login', { fail: req.query.fail });
});

app.post('/login/check-user', checkNotAuthenticated, (req, res) => {
    clientDB.get('SELECT id FROM users WHERE username = ?', req.body.email, (err, row) => {
        if(row) res.send(`
            <form method="POST" action="/login">
                <h2>Log in <button onClick="window.location.reload();" class="form-reset">Reload</button></h2>
                <label for="name/email">Name/E-mail</label>
                <input  type="name" name="email" id="email" autocomplete="on" value="${req.body.email}" readonly="true">
                <label for="Password">Password</label>
                <input type="password" name="password" id="password" autocomplete="on" placeholder="Start typing...">
                <button type="submit" class="form-submit">Log in</button>
            </form>
        `)
        if(!row) res.send(`
            <form>
                <h2>Log in <button onClick="window.location.reload();" class="form-reset">Reload</button></h2>
                <label for="name/email">Name/E-mail</label>
                <input  type="name" name="email" id="email" autocomplete="on" value="${req.body.email}" readonly="true">
                <p class='tcenter' style="margin-top: 25px;">No account found. Please <a href='/signup'>signup</a>.</p>
                <button onClick="window.location.reload();" class="form-submit">Reload page</button>
            </form>
    `)
    })
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
        successRedirect: '/login-success/log',
        failureRedirect: `/login?fail=password`,
        failureFlash: true
}));

app.get('/signup', checkNotAuthenticated, (req, res) => {
    res.render('public/signup', { error: null });
});

app.post('/signup/check-user', checkNotAuthenticated, (req, res) => {
    clientDB.get('SELECT id FROM users WHERE username = ?', req.body.email, (err, row) => {
        if(!row) { 
            res.send(`
                <form method="POST" action="signup">
                    <h2>Sign up <button onClick="window.location.reload();" class="form-reset">Reset</button> </h2>
                    <label for="name">Full Name</label>
                    <input type="text" name="name" value="${req.body.name}" readonly="true">
                    <label for="name/email">E-mail</label>
                    <input type="email" name="email" value="${req.body.email}" readonly="true">
                    <label for="Password">Password</label>
                    <input type="password" name="password" id="password" placeholder="Start typing..." required>
                    <div class="requirements">
                        <p class="tcenter"><span id="passwordLength">X</span>At least 8 characters</p>
                        <p class="tcenter"><span id="passwordUpperChar">X</span>Upper character</p>
                        <p class="tcenter"><span id="passwordHasNumber">X</span>Includes a number</p>
                        <p class="tcenter"><span id="passwordNotSpace">X</span>No spaces</p>
                    </div>
                    <label for="Password">Confirm Password <span id="message"></span></label>
                    <input type="password" placeholder="Start typing..." name="password_confirm" id="confirmPassword">

                    <button id="submit-button" class="form-submit">Sign up</button>
                </form>
                <script>
                    validationChecks = {
                        length: false,
                        upperChar: false,
                        number: false,
                        noSpaces: true,
                        confirm: false
                    }
                    $('#password, #confirmPassword').on('keyup', function () {
                        if ($('#password').val() == $('#confirmPassword').val() && $('#confirmPassword').val().length != 0) {
                            $('#confirmPassword').css('border', '1px green solid');
                            $('#message').html('Matches').css('color', 'green');
                            validationChecks.confirm = true
                        } else {
                            $('#confirmPassword').css('border', '1px red solid');
                            $('#message').html('');
                            $('#submit-button').css('cursor', 'not-allowed')
                            validationChecks.confirm = false
                        }

                        if(Object.values(validationChecks).every(item => item === true)) {
                            $('#submit-button').css('cursor', 'pointer')
                            $('#submit-button').attr('type', 'submit')
                        }
                    });
                    $('#password').on('keyup', function () {
                        if ($('#password').val().length >= 8) {
                            $('#passwordLength').html('✔').css('color', 'green');
                            validationChecks.length = true
                        } else {
                            $('#passwordLength').html('X').css('color', 'red');
                            validationChecks.length = false
                        }

                        let string = $('#password').val()

                        for(let str in string) {
                            if((string[str].toUpperCase() === string[str]) && !(string[str] >= '0' && string[str] <= '9') && !(string[str] == ' ')) {
                                $('#passwordUpperChar').html('✔').css('color', 'green')
                                validationChecks.upperChar = true
                                break
                            } else {
                                $('#passwordUpperChar').html('X').css('color', 'red')
                                validationChecks.upperChar = false
                            }
                        };
                        for(let str in string) {
                            if(string[str] >= '0' && string[str] <= '9') {
                                $('#passwordHasNumber').html('✔').css('color', 'green')
                                validationChecks.number = true
                                break
                            } else {
                                $('#passwordHasNumber').html('X').css('color', 'red')
                                validationChecks.number = false
                            }
                        };

                        if(!$('#password').val().includes(' ')) {
                            $('#passwordNotSpace').html('✔').css('color', 'green');
                            validationChecks.noSpaces = true
                        } else {
                            $('#passwordNotSpace').html('X').css('color', 'red');
                            validationChecks.noSpaces = false
                        }
                    });
                </script>
            `)
        } else {
            res.send(`
                <form>
                    <h2>Sign up <button onClick="window.location.reload();" class="form-reset">Reset</button> </h2>
                    <label for="name">Full Name</label>
                    <input type="text" name="name" value="${req.body.name}" readonly="true">
                    <label for="name/email" style="color: red;">E-mail is taken!</label>
                    <input type="email" name="email" value="${req.body.email}" readonly="true">
                    <p class="tcenter" style="margin-top: 20px;" id="redirect">Redirecting to login in <span id="countdown"></span> seconds. <a href="/login">Go there now</a>.</p>
                    <p class="tcenter" style="margin-top: 20px;"><a onClick="window.location.reload();" href="#">Cancel redirect and restart form</a></p>
                </form>
                <script>
                    document.getElementById('countdown').innerHTML = 5
                    let i = 1;
                    setInterval(() => {
                        if(i == 5){
                            window.location.pathname = "/login"
                        }
                        document.getElementById('countdown').innerHTML = 5 - i
                        i++;
                    }, 1000);
                </script>
            `)
        }
    })
})

app.post('/signup', checkNotAuthenticated, async (req,res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    clientDB.all(`INSERT INTO users(name, username, password, creation_date) VALUES ("${req.body.name}", "${req.body.email}", "${hashedPassword}", "${formatTime()}")`, [], err => {
                
    })
})

//PRIVATE
app.get('/home', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    gameDB.all('SELECT image_reference, airport_name, airport_icao FROM levels', [], (err, levels) => {
        if(err) add_user_log('ACCESS', err)
        clientDB.all(`SELECT * FROM leaderboard LEFT JOIN privacy ON leaderboard.personID = privacy.personID ORDER BY score DESC LIMIT 3;`, [], (err, leaderboard) => {
            leaderboard.forEach(leaderboardEntry => {
                if(leaderboardEntry.leaderboard != 'global') leaderboard.splice(leaderboard.indexOf(leaderboardEntry), 1)
            })
            if(err) add_user_log('ACCESS', err)
            clientDB.all(`SELECT users.id, users.name, users.username, users.pfp, users.last_played FROM users LEFT JOIN friends ON users.id = friends.passive_user WHERE friends.lead_user = ? AND friends.status = ?`, [req.user.id, "Active"], (err, following) => { // change 30 to current user
                if(err) add_user_log('ACCESS', err)
                res.render('private/home.ejs', { levels: levels, leaderboard: leaderboard, following: following });
            })
        })
    })
})

app.get('/leaderboard', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    clientDB.all(`SELECT * FROM leaderboard LEFT JOIN privacy ON leaderboard.personID = privacy.personID ORDER BY score DESC;`, [], (err, leaderboard) => {
        leaderboard.forEach(leaderboardEntry => {
            if(leaderboardEntry.leaderboard == 'private') leaderboard.splice(leaderboard.indexOf(leaderboardEntry), 1)
        })
        if(err) add_user_log('ACCESS', err)
        res.render('private/leaderboard.ejs', { leaderboard: leaderboard });
    })
})

app.get('/settings/:page', checkAuthenticated, (req, res) => { // to add checkAuthenticated
    if(req.params.page == 'profile') {
        clientDB.get(`SELECT id, name, username, pfp, cover_image FROM users WHERE id = ${req.user.id}`,(err, user) => {
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
        clientDB.get(`SELECT id, name, username, pfp, cover_image FROM users WHERE id = ${req.user.id}`,(err, user) => {
            if(err) add_user_log('PFP', err)
            clientDB.get('SELECT id FROM history WHERE personID = ?', req.user.id, (err, history) => {
                res.render('private/settings/general.ejs', { is_admin: req.user.is_admin, user: user, success: req.params.bool, history: history })
            })
        })
    } else if(req.params.page == 'admin') {
        clientDB.all('SELECT * FROM logs WHERE type == "ACCESS"', [], (err, user_access_logs) => {
            clientDB.all('SELECT * FROM logs WHERE type == "LOGIN" OR type == "LOGOUT"', [], (err, user_auth_logs) => {
                gameDB.all('SELECT id, airport_icao FROM levels', [], (err, levels) => {
                    clientDB.all('SELECT * FROM users', [], (err, users) => {
                        res.render('private/settings/admin.ejs', { user_auth_logs: user_auth_logs, user_access_logs: user_access_logs, levels: levels, all_users: users, is_admin: req.user.is_admin })
                    })
                })
            })
        })
    } else if(req.params.page == 'privacy') {
        clientDB.all(`SELECT * FROM privacy WHERE personID = ${req.user.id}`, [], (err, privacy) => {
            res.render('private/settings/privacy', { is_admin: req.user.is_admin, user: req.user, privacy: privacy[0] }) 
        })
    } else if(req.params.page == 'version') {
        clientDB.all('SELECT * FROM version_history ORDER BY date_added DESC', [], (err, version_history) => {
            res.render('private/settings/versionHistory', { is_admin: req.user.is_admin, entries: version_history })
        })
    } else {
        res.redirect('/error/settings')
    }
})

app.post('/backend/update/details/:id', checkAuthenticated, (req, res) => {
    if(req.body.name_before != req.body.name) {
        clientDB.all(`UPDATE users SET name = "${req.body.name}" WHERE id = ${req.params.id};`, [], err => {
            if(err) console.error(err);
        })
    }
    if(req.body.email_before != req.body.email) {
        clientDB.all(`UPDATE users SET username = "${req.body.email}" WHERE id = ${req.params.id};`, [], err => {
        })
    }

    res.send(`
        <form id="edit_details_form" hx-swap="outerHTML" hx-post="/backend/update/details/${req.params.id}">
            <div class="field">
                <p class="fs15">Your Name</p>
                <input type="text" name="name" value="${req.body.name}" class="field-entry" style="background-color: green;" required>
            </div>
            <div class="field">
                <p class="fs15">Email</p>
                <input type="email" name="email" value="${req.body.email}" class="field-entry" style="background-color: green;" required>
            </div>
            <button type="submit">Apply changes</button>
        </form>
        <script src="https://code.jquery.com/jquery-3.7.1.js" integrity="sha256-eKhayi8LEQwp4NKxN+CfCh+3qOVUtJn3QNZ0TciWLP4=" crossorigin="anonymous"></script>
        <script>
            setTimeout(() => {
                $('.field-entry').css('background-color', 'rgba(127, 127, 127, 0.266)')
            }, 1200)
        </script>
    `)
})

app.post('/backend/update/user/:option/:id', checkAuthenticated, (req, res) => {
    if(req.params.option != 'privacy') {
        if(isImage(req.body.url)) {
            if(req.params.option == 'profile-picture') {
                clientDB.run(`UPDATE users SET pfp = '${req.body.url}' WHERE id = ${req.params.id}`, [], err => {})
            }
            if(req.params.option == 'cover-picture') {
                clientDB.run(`UPDATE users SET cover_image = '${req.body.url}' WHERE id = ${req.params.id}`, [], err => {})
            }
            res.send(`
                <form id="form-change-pfp" hx-swap="outerHTML" hx-post="/backend/update/user/image/${req.params.id}">
                    <div class="container">
                        <img src="${req.body.url}" alt="" class="change_image changed">
                    </div>
                    <div class="container">
                        <input type="url" name="url" placeholder="Link" class="fs15 text-center color-black change_image_entry" value="${req.body.url}" style="background-color: green;" required>
                        <button type="submit" style="width: 20%;">✔</button>
                    </div>
                </form>
                <script src="https://code.jquery.com/jquery-3.7.1.js" integrity="sha256-eKhayi8LEQwp4NKxN+CfCh+3qOVUtJn3QNZ0TciWLP4=" crossorigin="anonymous"></script>
                <script>
                    setTimeout(() => {
                        $('.change_image').removeClass('changed')
                    }, 500)
                    setTimeout(() => {
                        $('.change_image_entry').css('background-color', 'rgba(127, 127, 127, 0.266)')
                    }, 1200)
                </script>
            `)
        }
    
    } else {
        clientDB.all(`UPDATE privacy SET profile = "${req.body.privacy_setting_profile}", history = "${req.body.privacy_setting_history}", leaderboard = "${req.body.privacy_setting_leaderboard}" WHERE personID = ${req.user.id}`, [], (err) => {
            res.redirect('/settings/privacy')
        })
    }
})

app.post('/backend/reset/user/:option/:id', checkAuthenticated, (req, res) => {
    let defaultImage;
    if(req.params.option == 'profile-picture' || req.params.option == 'cover-image') {
        if(req.params.option == 'profile-picture') {
            defaultImage = 'https://img.freepik.com/premium-vector/male-avatar-icon-unknown-anonymous-person-default-avatar-profile-icon-social-media-user-business-man-man-profile-silhouette-isolated-white-background-vector-illustration_735449-122.jpg?w=1800'
            clientDB.run(`UPDATE users SET pfp = '${defaultImage}' WHERE id = ${req.params.id}`, [], err => {})
        }
        if(req.params.option == 'cover-image') {
            defaultImage = 'https://images.unsplash.com/photo-1540575861501-7cf05a4b125a?q=80&w=1740&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D.jpg'
            clientDB.run(`UPDATE users SET cover_image = '${defaultImage}' WHERE id = ${req.params.id}`, [], err => {})
        }
        res.send(`
            <form class="admin-reset-image" hx-swap="outerHTML" hx-post="/backend/reset/user/${req.params.option}/${req.params.id}">
                <h1 class="title tcenter">${req.params.option}</h1>
                <img src="${defaultImage}" alt="" class="changed changed_image">
                <button type="submit" class="reset-image" style="background-color: green;">Reset</button>
            </form>
            <script src="https://code.jquery.com/jquery-3.7.1.js" integrity="sha256-eKhayi8LEQwp4NKxN+CfCh+3qOVUtJn3QNZ0TciWLP4=" crossorigin="anonymous"></script>
            <script>
                setTimeout(() => {
                    $('.reset-image').css('background-color', 'white')
                }, 1200)
                setTimeout(() => {
                    $('.changed_image').removeClass('changed')
                }, 500)
            </script>
        `)
    } else {
        clientDB.all('DELETE FROM leaderboard WHERE personID = ?', req.user.id, err => {  })
        clientDB.all('DELETE FROM history WHERE personID = ?', req.user.id, err => {  })
        res.redirect('/settings/general')
    }
})

app.get('/settings/admin/p/:id', checkAuthenticated, (req, res) => {
    clientDB.all('SELECT * FROM leaderboard WHERE personID = ?', req.params.id, (err, leaderboard) => {
        if(err) user_access_logs('ACCESS', err)
        clientDB.all('SELECT id, cover_image, pfp, name, username, last_played, best_played, points, creation_date, is_admin FROM users WHERE id = ?', req.params.id, (err, user) => {
            if(err) user_access_logs('ACCESS', err)
            clientDB.all('SELECT * FROM history WHERE personID = ?', req.params.id, (err, history) => {
                if(err) user_access_logs('ACCESS', err)
                res.render('private/settings/manage_profile.ejs', { user: user, leaderboard: leaderboard, history: history, is_admin: req.user.is_admin, userID: req.user.id })
            })
        })
    })
})

app.post('/reset_points/:id', checkAuthenticated, (req, res) => {
    clientDB.all(`UPDATE users SET points = 0 WHERE id = ${req.params.id};`, [], err => {
        if(!err) res.redirect(`/settings/admin/p/${req.params.id}`)
    })
})

app.post('/edit_level_image/:id', checkAuthenticated, (req, res) => {
    if(isImage(req.body.url)) {
        gameDB.run(`UPDATE levels SET image_reference = '${req.body.url}' WHERE id = ${req.params.id}`, [], err => {
            if(!err) res.redirect(`/admin/edit/${req.params.id}/details`)
        })
    } else {
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
    clientDB.get(`SELECT id, name, username, pfp, cover_image FROM users WHERE id = ${req.params.id}`,(err, user) => {
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

app.get('/end', checkAuthenticated, (req, res) => {
    clientDB.all(`INSERT INTO history (date, score, level, time_taken, personID) VALUES('${formatTime()}', ${req.query.score}, '${req.query.level}', '${convertSecToMin(req.query.time)}', ${req.user.id});`, [], err => {})
    clientDB.get('SELECT points FROM users WHERE id = ?', req.user.id, (err, row) => {
        if(err) add_user_log('ACCESS', err)
        clientDB.all('UPDATE users SET points = ? WHERE id = ?', parseInt(row.points) + parseInt(req.query.score), req.user.id, err => { }) 
    })

    clientDB.get(`SELECT * FROM history WHERE personID = ${req.user.id} ORDER BY score DESC;`, [], (err, row) => {
        clientDB.all(`UPDATE users SET best_played = '${row.level}' WHERE id = ${req.user.id}`, [], (err) => { }) // undefined FIX THIS
    })

    clientDB.all(`UPDATE users SET last_played = '${req.query.level}' WHERE id = ${req.user.id}`, [], (err) => {  }) // undefined FIX THIS
    clientDB.all('DELETE FROM leaderboard WHERE personID = ?', req.user.id, err => {  })
    clientDB.all(`INSERT INTO leaderboard (name, date, score, level, personID) VALUES('${req.user.name}', '${formatTime()}', ${req.query.score}, '${req.query.level}', ${req.user.id});`, [], err => { })

    gameDB.all('SELECT image_reference FROM levels WHERE airport_name=?', req.query.level, (err, image) => {
        res.render('private/terminate_play.ejs', { level: req.query.level, image: image[0].image_reference, score: req.query.score, time: convertSecToMin(req.query.time), reason: req.query.reason })
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

app.get('/remove_following/:id', checkAuthenticated, (req, res) => {
    clientDB.all('DELETE FROM friends WHERE lead_user = ? AND passive_user = ?', [req.user.id, req.params.id], err => { 
        if(err) add_user_log('ACCESS', err)
        res.redirect('/settings/friends')
    })
})

app.get('/remove_follower/:id', checkAuthenticated, (req, res) => {
    clientDB.all('DELETE FROM friends WHERE lead_user = ? AND passive_user = ?', [req.params.id, req.user.id], err => { 
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
    })
})



app.get('/*', (req, res) => {
    res.status(404)
    res.render('public/error')
})

// Get date now and format it to custom
function formatTime() {
    const date = new Date();
    const day = `${date.getFullYear()}-${date.getMonth()}-${date.getDay()}`
    const hours = date.getHours()
    const mins = `${date.getMinutes()<10?'0':''}${date.getMinutes()}`
    return `${day} ${hours}:${mins}`
}

function convertSecToMin(seconds) {
    let minutes = Math.floor(seconds / 60);
    let extraSeconds = seconds % 60;
    minutes = minutes < 10 ? "0" + minutes : minutes;
    extraSeconds = extraSeconds< 10 ? "0" + extraSeconds : extraSeconds;
    return `${minutes}m ${extraSeconds}s`
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