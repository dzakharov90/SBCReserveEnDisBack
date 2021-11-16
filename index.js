require('dotenv').config()
const express = require('express');
const compression = require('compression');
const { MongoClient } = require('mongodb');
const jsonwebtoken = require('jsonwebtoken');
const jwt = require('jsonwebtoken');
const jwt_decode = require('jwt-decode');
const fs = require('fs');
const fetch = require("node-fetch");
const conf = require('./config.json');
const FormData = require('form-data');  

const app = express()
const port = process.env.PORT
//const mdb = new MongoClient("mongodb+srv://<username>:<password>@<your-cluster-url>/test?retryWrites=true&w=majority");
const mdb = new MongoClient(`mongodb://${conf.mongodb.host}`);

const accessTokenSecret = 'ApifonicaF0r3v3r2022!!';

const helmet = require('helmet'),
    morgan = require('morgan'),
    cors = require('cors'),
    bodyParser = require('body-parser');
const { finished } = require('stream');
var ps = require('ps-node');
const { config } = require('dotenv');

var corsOptions = {
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    exposedHeaders: ['Content-Type', 'Access-Control-Allow-Headers', 'Authorization', 'X-Requested-With','x-auth-token'],
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}

app.use(compression())

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.disable('x-powered-by');

// adding Helmet to enhance your API's security
app.use(helmet());

// using bodyParser to parse JSON bodies into JS objects
//app.use(bodyParser.json());

// enabling CORS for all requests
app.use(cors(corsOptions), function(req, res, next) {
  console.log("OPTIONS");
  console.log(req.query);
  //console.log(req);
  next();
});

// adding morgan to log HTTP requests
app.use(morgan('combined'));

app.post('/api/v1/user_auth', cors(corsOptions), (req, res) => {
    (async () => {
        try {
            // Connect to the MongoDB cluster
            if (!req.query.username) {
                res.status(403).json({data :{ message: 'auth failed. username param not defined' }, result: 'fail'});
            } else if (!req.query.hash) {
                res.status(403).json({data :{ message: 'auth failed. password param not defined' }, result: 'fail'});
            } else {
                const login = req.query.username
                const hash = req.query.hash
                await mdb.connect();
                // Make the appropriate DB calls
                //documentList = await mdb.db().reserve().listDocuments();
                const database = mdb.db("reserve");
                const users = database.collection("users");
                const query = { username: login };
                const userdoc = await users.findOne(query);
                console.log(userdoc);
                if (userdoc.ha1_hash === hash) {
                    const accessToken = jwt.sign({ role: userdoc.role, username: userdoc.username }, accessTokenSecret, { expiresIn: 3600 })
                    res.status(200).json({data :{ token: accessToken, role: userdoc.role }, result: 'success'});
                } else {
                    res.status(403).json({data :{ message: 'Incorrect username or password' }, result: 'fail'});
                }
            }
        } catch (e) {
            console.error(e);
        } finally {
            await mdb.close();
        }
    })();
})

app.get('/api/v1/get_status', cors(corsOptions), (req, res) => {
    var token = req.headers['x-auth-token'];
    if (!token) {
        res.status(401).send({ data: { message: 'Auth token required.'}, result: 'failed'});
    } else if (token) {
        jwt.verify(token, accessTokenSecret, function(err, decoded) {
            if (err) {
                res.status(401).send({ data: {auth: false, message: 'Failed to authenticate token or token expired.'}, result: 'failed' });
            } else {
                (async () => {
                    try {
                        await mdb.connect();
                        // Make the appropriate DB calls
                        //documentList = await mdb.db().reserve().listDocuments();
                        const database = mdb.db("reserve");
                        const status = database.collection("status");
                        const userdoc = await status.findOne();
                        console.log(userdoc);
                        res.status(200).json({data :{ status: userdoc.status }, result: 'success'});
                    } catch (e) {
                        console.error(e);
                    } finally {
                        await mdb.close();
                    }
                })();
            }
        });
    }
})

app.get('/api/v1/reserveenable', cors(corsOptions), (req, res) => {
    var token = req.headers['x-auth-token'];
    if (!token) {
        res.status(401).send({ data: { message: 'Auth token required.'}, result: 'failed'});
    } else if (token) {
        jwt.verify(token, accessTokenSecret, function(err, decoded) {
            if (err) {
                res.status(401).send({ data: {auth: false, message: 'Failed to authenticate token or token expired.'}, result: 'failed' });
            } else {
                (async () => {
                    try {
                        const form = new FormData();
                        const buffer = fs.readFileSync('./enreserve.ini');
                        const fileName = 'enreserve.ini';
                        form.append('file', buffer, {
                            contentType: 'text/plain',
                            name: 'file',
                            filename: fileName,
                        });
                        fetch(`http://${conf.sbc.host}/api/v1/files/cliScript/incremental`, {
                            method: 'PUT',
                            headers: {
                                'Authorization': 'Basic ' + btoa(`${conf.sbc.username}:${conf.sbc.password}`)
                            },
                            body: form
                        })
                        .then(data => data.json())
                        .then(data => {
                            console.log('resposce:', data);
                            (async () => {
                                await mdb.connect();
                                // Make the appropriate DB calls
                                //documentList = await mdb.db().reserve().listDocuments();
                                const database = mdb.db("reserve");
                                const status = database.collection("status");
                                const filter = { status: "Reserve disabled" };
                                const options = { upsert: true };
                                const updateDoc = {
                                    $set: {
                                    status: 'Reserve enabled'
                                    },
                                };
                                const userdoc = await status.updateOne(filter, updateDoc, options);
                                console.log(userdoc);
                                res.status(200).json({data :{ status: `MongoDB: updated ${userdoc.modifiedCount} document(s). SBC: ${data.description}` }, result: 'success'});
                            })();
                        })
                        .catch( err => {
                            res.status(500).json({data :{ status: `failed` + err }, result: 'fail'});
                        })
                    } catch (e) {
                        res.status(500).json({data :{ status: `failed` + e }, result: 'fail'});
                    } finally {
                        await mdb.close();
                    }
                })();
            }
        });
    }
})

app.get('/api/v1/reserveDisable', cors(corsOptions), (req, res) => {
    var token = req.headers['x-auth-token'];
    if (!token) {
        res.status(401).send({ data: { message: 'Auth token required.'}, result: 'failed'});
    } else if (token) {
        jwt.verify(token, accessTokenSecret, function(err, decoded) {
            if (err) {
                res.status(401).send({ data: {auth: false, message: 'Failed to authenticate token or token expired.'}, result: 'failed' });
            } else {
                (async () => {
                    try {
                        const form = new FormData();
                        const buffer = fs.readFileSync('./disreserve.ini');
                        const fileName = 'disreserve.ini';
                        form.append('file', buffer, {
                            contentType: 'text/plain',
                            name: 'file',
                            filename: fileName,
                        });
                        fetch(`http://${conf.sbc.host}/api/v1/files/cliScript/incremental`, {
                            method: 'PUT',
                            headers: {
                                'Authorization': 'Basic ' + btoa(`${conf.sbc.username}:${conf.sbc.password}`)
                            },
                            body: form
                        })
                        .then(data => data.json())
                        .then(data => {
                            console.log('resposce:', data);
                            (async () => {
                                await mdb.connect();
                                // Make the appropriate DB calls
                                //documentList = await mdb.db().reserve().listDocuments();
                                const database = mdb.db("reserve");
                                const status = database.collection("status");
                                const filter = { status: "Reserve enabled" };
                                const options = { upsert: true };
                                const updateDoc = {
                                    $set: {
                                    status: 'Reserve disabled'
                                    },
                                };
                                const userdoc = await status.updateOne(filter, updateDoc, options);
                                console.log(userdoc);
                                res.status(200).json({data :{ status: `MongoDB: updated ${userdoc.modifiedCount} document(s). SBC: ${data.description}` }, result: 'success'});
                            })();
                        })
                        .catch( err => {
                            res.status(500).json({data :{ status: `failed` + err }, result: 'fail'});
                        })
                    } catch (e) {
                        console.error(e);
                    } finally {
                        await mdb.close();
                    }
                })();
            }
        });
    }
})

ps.lookup({
    command: 'node',
    psargs: 'ux'
    }, function(err, resultList ) {
    if (err) {
        throw new Error( err );
    }

    resultList.forEach(function( process ){
        if( process ){
            //console.log( 'PID: %s, COMMAND: %s, ARGUMENTS: %s', process.pid, process.command, process.arguments );
        }
    });
});

var address, os = require('os'),ifaces = os.networkInterfaces();
    for (var dev in ifaces) {
        // ... and find the one that matches the criteria
        var iface = ifaces[dev].filter(function(details) {
            return details.family === 'IPv4' && details.internal === false;
        });
    
        if(iface.length > 0) address = iface[0].address;
    }

app.listen(port, () => console.log(`SBC Reserve Backend started with PID ${process.pid} and API available on http://${address}:${port}`))