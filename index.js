const path = require('path')
const jwt = require('jsonwebtoken');
const passport = require('passport')
const ActiveDirectoryStrategy = require('passport-activedirectory')

exports._jwt = {
    init_express_session: function(app) {
        var express_session = require('express-session')
        var is_secure = false
        if (process.env.APP_ENV === "DEVELOPMENT" || process.env.APP_ENV === "TEST" || process.env.APP_ENV === "PREPROD" || process.env.APP_ENV === "PRODUCTION") {
            is_secure = true
        }
        app.use(express_session({
            secret: process.env.SESSION_COOKIE_SECRET,
            resave: false,
            saveUninitialized: true,
            // Mitigate identification of tools used
            name: process.env.SESSION_COOKIE_NAME,
            cookie: {
                path: "/", // Cookies can only be gotten from this site
                httpOnly: true, // Cookie is not accessable to script on the client side, mititgates XXS attacks
                secure: is_secure, // Only allow cookies to be presented over HTTPS
                maxAge: process.env.SESSION_COOKIE_TIMEOUT_MS * 1
            }
        }));
    },
    authorize: function(req, res, next) {

        var token = '';
        //check headers
        var authHeader = req.headers.authorization;
        if (authHeader) {
            token = authHeader.split(' ')[1];
            jwt.verify(token, process.env.JWT_COOKIE_SECRET, (err, user) => {
                if (err) {
                    res.sendFile(path.join(__dirname, '../../', '/content/pages/login.html'));
                }
                req.user = user;
                next();
            });
        } else {
            // check for a cookie
            var cookies = req.headers.cookie
            if (cookies) {
                var cookie_list = cookies.split(';')
                var found = false
                var found_val = ''
                if (cookie_list.length > 0) {
                    cookie_list.forEach(element => {
                        var cookie = element.trim()
                        var cookie_parts = cookie.split('=')
                        if (cookie_parts[0] === process.env.JWT_COOKIE_NAME) {
                            found = true
                            found_val = cookie_parts[1]
                            token = cookie_parts[1]
                        }
                    });

                    if (found) {
                        jwt.verify(token, process.env.JWT_COOKIE_SECRET, (err, user) => {
                            if (err) {
                                console.log("Error on verify token." + err)
                                res.clearCookie(process.env.JWT_COOKIE_NAME);
                                res.sendFile(path.join(__dirname, '../../', '/content/pages/login.html'));
                            } else {
                                req.user = user;
                                next();
                            }
                        });
                    } else {
                        console.log("Token not found")
                        res.sendFile(path.join(__dirname, '../../', '/content/pages/login.html'));
                    }
                }
            } else {
                console.log("No cookies")
                res.sendFile(path.join(__dirname, '../../', '/content/pages/login.html'));
            }
        }

    },
    sign:function(payload,secret,options){
        jwt.sign(payload,secret,options)
    }
}

exports._ad = {
    passport: function (app) {

        //PASSPORT
        app.use(passport.initialize());
        app.use(passport.session());

        passport.serializeUser(function (user, done) {
            done(null, user);
        });
        passport.deserializeUser(function (user, done) {
            done(null, user);
        });
        passport.use(new ActiveDirectoryStrategy({
            integrated: false,
            ldap: {
                url: process.env.AD_URL,
                baseDN: process.env.AD_BASE_DN,
                username: process.env.AD_UN,
                password: process.env.AD_PW
            }
        }, function (profile, ad, done) {
            var profile_dn = profile._json.dn
            profile_dn = profile_dn.replace("=", "%3D") // escape this else it gives and error on the isusermemberof
            ad.isUserMemberOf(profile_dn, 'AccessGroup', function (err, isMember) {
                if (err) {
                    return done(err)
                } else {
                    // console.log(profile)
                    if (profile) {
                        if (profile._json) {
                            if (profile._json.displayName) {
                                console.log("User logged on : " + profile._json.displayName)
                            }
                        }
                    }
                    return done(null, profile)
                }
            })
        }, function (err) {
            //res.status(401).send('Not Authenticated')
            var jsondata = {
                "success": "false",
                "code": "401",
                "error": ""
            }
            res.json(jsondata);
        }))


    },
}