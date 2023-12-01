const path = require('path')
const jwt = require('jsonwebtoken');
const passport = require('passport')
const ActiveDirectoryStrategy = require('passport-activedirectory')

exports._jwt = {
    init_express_session: function (app) {
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
    authorize: function (req, res, next) {

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
    sign: function (payload, secret, options) {
        return jwt.sign(payload, secret, options)
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
    authenticate: function (strategy, options) {
        return passport.authenticate(strategy, options)
    }
}

exports.html_validators = {
    auth_wrapper: function(req, res, callback) {
        var token = req.headers["Authorization"] || req.headers["authorization"];
        if (token) {
            if (token === 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=') {
                callback("Failed to authenticate. username and password not allowed.", true, 403);
            } else {
                var toten_list = process.env.SECURITY_BASIC_AUTH_INC.split(",");
                // console.log(process.env.SECURITY_BASIC_AUTH_INC);
                // console.log(toten_list);
                if (toten_list.length > 0) {
                    var found_token = false;
                    toten_list.forEach((element) => {
                        if (token === element) {
                            if (element === 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=') {
                                found_token = false;
                            } else {
                                found_token = true;
                            }
                        }
                    });
                    if (found_token === true) {
                        callback("all good", false, 200);
                    } else {
                        callback("Failed to authenticate.", true, 403);
                    }
                } else {
                    callback("No authentication provided.", true, 403);
                }
            }
        } else {
            callback("No authentication provided.", true, 403);
        }
    },
    auth_wrapper_async: async function(req, res) {
        var response_data = {
            jsonResult: "",
            haserror: "",
            code: "",
        }
        var token = req.headers["Authorization"] || req.headers["authorization"];
        if (token) {
            if (token === 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=') {
                response_data.jsonResult = "Failed to authenticate. username and password not allowed."
                response_data.haserror = true
                response_data.code = 403
                return response_data
            } else {
                var toten_list = process.env.SECURITY_BASIC_AUTH_INC.split(",");
                // console.log(process.env.SECURITY_BASIC_AUTH_INC);
                // console.log(toten_list);
                if (toten_list.length > 0) {
                    var found_token = false;
                    toten_list.forEach((element) => {
                        if (token === element) {
                            if (element === 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=') {
                                found_token = false;
                            } else {
                                found_token = true;
                            }
                        }
                    });
                    if (found_token === true) {
                        response_data.jsonResult = "All good."
                        response_data.haserror = false
                        response_data.code = 200
                        return response_data
                    } else {
                        response_data.jsonResult = "Failed to authenticate."
                        response_data.haserror = true
                        response_data.code = 403
                        return response_data
                    }
                } else {
                    response_data.jsonResult = "No authentication provided."
                    response_data.haserror = true
                    response_data.code = 403
                    return response_data
                }
            }
        } else {
            response_data.jsonResult = "No authentication provided."
            response_data.haserror = true
            response_data.code = 403
            return response_data
        }
    },
}

exports.html_wrappers = {
    result_wrapper: function(res, jsonResult, haserror, code) {
        if (haserror) {
            res.status(code).type('application/json').json({
                success: false,
                httpStatusCode: code,
                error: {
                    message: jsonResult
                }
            });
        } else {
            res.status(code).type('application/json').json({
                success: true,
                httpStatusCode: code,
                data: jsonResult
            });
        }
    },
    result_wrapper_xml: function(res, jsonResult, haserror, code) {
        if (!haserror) {
            res.status(code).type('text/xml').send(jsonResult);
        } else {
            res.status(code).type('application/json').json({
                success: true,
                httpStatusCode: code,
                data: jsonResult
            });
        }
    },
    result_wrapper_async: async function(res, jsonResult, haserror, code) {
        if (haserror) {
            res.status(code).type('application/json').json({
                success: false,
                httpStatusCode: code,
                error: {
                    message: jsonResult
                }
            });
        } else {
            res.status(code).type('application/json').json({
                success: true,
                httpStatusCode: code,
                data: jsonResult
            });
        }
    }
}