/*
 * Note:
 * This is for demo purpose
 * - Password hashing is not implemented
 */

var config = require('config');
var http = require("http");
var express = require('express');
var bearerToken = require('express-bearer-token');
var app = express();
var mysql = require('mysql');
var bodyParser = require('body-parser');
var validator = require('email-validator');
var auth = require('basic-auth');

var helperCommon = require('./helper/common');

var MISSING_REQUIRED_FIELD = 'Missing required field: ';
var MIN_PASSWORD_LENGTH = 6;

var connection = mysql.createConnection({
    host: config.get('DbConfig.MySqlMain.Host'),
    port: config.get('DbConfig.MySqlMain.Port'),
    user: config.get('DbConfig.MySqlMain.User'),
    password: config.get('DbConfig.MySqlMain.Password'),
    database: config.get('DbConfig.MySqlMain.Database')
});

connection.connect(function (err) {
    if (err) throw err;

    console.log(
        'Connected to mysql server: ' +
        config.get('DbConfig.MySqlMain.Host') + ':' +
        config.get('DbConfig.MySqlMain.Port') + ', ' +
        'database: ' + config.get('DbConfig.MySqlMain.Database'));

    /*
     * Create Customer Table
     * Note: DEFAULT CURRENT_TIMESTAMP NOT SUPPORTED
     */
    var sql = `CREATE TABLE IF NOT EXISTS customer (
        ID int NOT NULL AUTO_INCREMENT,
        NAME varchar(255) NOT NULL,
        EMAIL varchar(255) NOT NULL UNIQUE,
        PASSWORD varchar(255) NOT NULL,
        TOKEN varchar(32) NULL,
        CREATED_AT datetime NOT NULL,
        UPDATED_AT datetime NOT NULL,
        PRIMARY KEY (Id)
      ) AUTO_INCREMENT=1;`;

    connection.query(sql, function (err, result) {
        if (err) throw err;
    });
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bearerToken());

// Add headers
app.use(function (req, res, next) {

    // Website you wish to allow to connect
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.setHeader('Access-Control-Allow-Headers', '*');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);

    // Pass to next layer of middleware
    next();
});

var server = app.listen(
    config.get('Server.Port'),
    config.get('Server.Host'),
    function () {
        var host = server.address().address
        var port = server.address().port

        console.log("App listening at http://%s:%s", host, port)
    });


// REST API for get customer token
app.get('/v1/oauth/token', function (req, res) {
    var credentials = auth(req);

    if (credentials) {
        connection.query(
            'SELECT Token from customer where Email=? and Password=? LIMIT 1', [credentials.name, credentials.pass],
            function (error, results, fields) {
                if (error) {
                    return res.status(400).json(helperCommon.formatRestApiSqlError(error));
                }

                if (results.length) {
                    connection.query('UPDATE customer SET Token=? where Email=? and Password=?', [helperCommon.generateUserAuthToken(), credentials.name, credentials.pass],
                        function (error, results, fields) {
                            if (error) {
                                return res.status(400).json(helperCommon.formatRestApiSqlError(error));
                            }

                            connection.query(
                                'SELECT Token from customer where Email=? and Password=? LIMIT 1', [credentials.name, credentials.pass],
                                function (error, results, fields) {
                                    return res.status(200).json({
                                        tokenType: 'Bearer',
                                        accessToken: results[0].Token
                                    })
                                });
                        });
                } else {
                    return res.status(401).json(helperCommon.formatRestApiError(
                        'E1001',
                        'Invalid username or password'));
                }
            });
    } else {
        return res.status(401).json(helperCommon.formatRestApiError(
            'E1001',
            'Invalid username or password'));
    }
});


// REST API for revoke customer token
app.post('/v1/oauth/revoke', function (req, res) {
    var bearerToken = req.token;

    if (bearerToken) {
        connection.query('SELECT name,email from customer where Token=? LIMIT 1', [bearerToken],
            function (error, results, fields) {
                if (error) {
                    return res.status(400).json(helperCommon.formatRestApiSqlError(error));
                }

                connection.query('UPDATE customer SET Token=NULL where Token=?', [bearerToken],
                    function (error, results, fields) {
                        if (error) {
                            return res.status(400).json(helperCommon.formatRestApiSqlError(error));
                        }

                        return res.status(200).json(helperCommon.formatRestApiSuccess(
                            true));
                    });
            });
    } else {
        return res.status(400).json(helperCommon.formatRestApiError(
            'E1002',
            'Missing bearer token'));
    }
});


// REST API for get customer own profile
app.get('/v1/customer/me', function (req, res) {
    var bearerToken = req.token;

    if (bearerToken) {
        connection.query('SELECT name,email from customer where Token=? LIMIT 1', [bearerToken],
            function (error, results, fields) {
                if (error) {
                    return res.status(400).json(helperCommon.formatRestApiSqlError(error));
                }

                if (results.length) {
                    return res.status(200).json(helperCommon.formatRestApiSuccess(
                        results[0]));
                } else {
                    return res.status(401).json(helperCommon.formatRestApiError(
                        'E0010',
                        'Invalid access token'));
                }
            });
    } else {
        return res.status(400).json(helperCommon.formatRestApiError(
            'E1002',
            'Missing bearer token'));
    }
});


// REST API for customer registration
app.post('/v1/customer', function (req, res) {
    var params = req.body;

    if (!params.email) {
        return res.status(400).json(helperCommon.formatRestApiError(
            'E0001',
            MISSING_REQUIRED_FIELD + 'email'));
    }

    if (params.email) {
        if (!validator.validate(req.body.email)) {
            return res.status(400).json(helperCommon.formatRestApiError(
                'E0002',
                'Invalid email address'));
        }
    }

    if (!params.name) {
        return res.status(400).json(helperCommon.formatRestApiError(
            'E0003',
            MISSING_REQUIRED_FIELD + 'name'));
    }

    if (!params.password) {
        return res.status(400).json(helperCommon.formatRestApiError(
            'E0004',
            MISSING_REQUIRED_FIELD + 'password'));
    }

    if (params.password.length < MIN_PASSWORD_LENGTH) {
        return res.status(400).json(helperCommon.formatRestApiError(
            'E0005',
            'Minimum password length is ' + MIN_PASSWORD_LENGTH));
    }

    params.created_at = helperCommon.getCurrentDateTimeUtc();
    params.updated_at = helperCommon.getCurrentDateTimeUtc();

    connection.query('INSERT INTO customer SET ?', params, function (error, results, fields) {
        if (error) {
            return res.status(400).json(helperCommon.formatRestApiSqlError(error));
        }

        return res.status(200).json({
            email: params.email
        });
    });
});