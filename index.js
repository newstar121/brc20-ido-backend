const express = require("express");
const app = express();
const port = 5055;
const cors = require("cors");
const passport = require("passport")
const passportJWT = require("passport-jwt");
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const keys = require("./keys")
const router = express.Router()
const authRouter = express.Router()
const adminRouter = express.Router()
const jwt = require("jsonwebtoken")
const dotenv = require('dotenv')
const fs = require('fs');
const bcrypt = require('bcryptjs')
const path = require('path')
const axios = require('axios')

dotenv.config()
const presale_account_address = process.env.PRESALE_ACCOUNT_ADDRESS
const public_key = process.env.PUBLIC_KEY;
const private_key = process.env.PRIVATE_KEY;
const username = process.env.USER_NAME;
const password = process.env.PASSWORD;

const PRESALE_TYPE = {
    public: 'public',
    whitelist: 'whitelist'
}

let database = [];
let basicData;
app.use(express.static(__dirname));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(passport.initialize());


app.use(express.static("build"));

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: keys.secretOrKey
}, (jwtPayload, cb) => {
    if (jwtPayload.address) {
        return cb(null, jwtPayload.address)
    } else {
        return cb(null, jwtPayload.username)
    }
}
));

router.get("/getAccountAddress", (req, res) => {
    const payload = { address: presale_account_address }; // Create JWT Payload
    // Sign Token
    jwt.sign(
        payload,
        keys.secretOrKey,
        { expiresIn: 3600 * 1000 },
        (err, token) => {
            if (err) {
                console.log('getAccountAddress error', err)
                res.status(201).json({
                    success: false,
                    msg: err
                });
            } else {
                res.json({
                    success: true,
                    token: 'Bearer ' + token,
                    address: presale_account_address,
                });
            }
        }
    );
});

router.get("/getPresaleTime", (req, res) => {
    let currentTs = (new Date()).getTime();
    if (basicData.presale_end_time <= currentTs && basicData._presale_end_time <= currentTs) {
        res.json({
            success: false,
            msg: 'Presale ended'
        });
    } else {
        res.json({
            success: true,
            startTimeStamp: (basicData.presale_start_time - currentTs),
            endTimeStamp: (basicData.presale_end_time - currentTs),
            _startTimeStamp: (basicData._presale_start_time - currentTs),
            _endTimeStamp: (basicData._presale_end_time - currentTs)
        });
    }
});

router.get("/getData", (req, res) => {
    let address = req.query.address;
    try {
        let data = {
            total: 0.0,
            contributor: 0,
            raisingPercentage: 0,
            funds: 0,
            investment: 0,
            received: 0,
            ratio: 0,
            max: 0,
            min: 0,
            presale_start_time: (new Date()).getTime(),
            presale_end_time: (new Date()).getTime(),

            _total: 0.0,
            _contributor: 0,
            _raisingPercentage: 0,
            _funds: 0,
            _investment: 0,
            _received: 0,
            _ratio: 0,
            _max: 0,
            _min: 0,
            _presale_start_time: (new Date()).getTime(),
            _presale_end_time: (new Date()).getTime()
        }

        database.forEach((item) => {
            if (item.type === PRESALE_TYPE.whitelist) data._total += (item.bitcoin) * Math.pow(10, 6);
            else data.total += (item.bitcoin) * Math.pow(10, 6);
        });

        data.total /= Math.pow(10, 6);
        data._total /= Math.pow(10, 6);

        data.contributor = database.filter((item) => item.type === PRESALE_TYPE.public).length || 0;
        data._contributor = database.filter((item) => item.type === PRESALE_TYPE.whitelist).length || 0;

        data.funds = basicData.funds;
        data._funds = basicData._funds;

        data.raisingPercentage = (data.total / data.funds * 100).toFixed(2) || 0;
        data._raisingPercentage = (data._total / data._funds * 100).toFixed(2) || 0;

        let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address && accountInfo.type === PRESALE_TYPE.public)
        data.investment = accountIndex > -1 ? database[accountIndex].bitcoin || 0 : 0;
        data.received = accountIndex > -1 ? database[accountIndex].brc20 || 0 : 0;

        accountIndex = database.findIndex((accountInfo) => accountInfo.address == address && accountInfo.type === PRESALE_TYPE.whitelist)
        data._investment = accountIndex > -1 ? database[accountIndex].bitcoin || 0 : 0;
        data._received = accountIndex > -1 ? database[accountIndex].brc20 || 0 : 0;

        data.ratio = basicData.ratio;
        data._ratio = basicData._ratio;

        data.min = basicData.min;
        data._min = basicData._min;

        data.max = basicData.max;
        data._max = basicData._max;

        data.presale_start_time = basicData.presale_start_time;
        data.presale_end_time = basicData.presale_end_time;

        data._presale_start_time = basicData._presale_start_time;
        data._presale_end_time = basicData._presale_end_time;

        res.json({
            success: true,
            data: data
        });
    } catch (error) {
        res.json({
            success: false,
            msg: 'Getting data failed'
        });
        console.log('getData error', error)
    }
});


router.get("/login", (req, res) => {
    let loginUsername = req.query.username;
    let hashPassword = req.query.password;
    // let myHashedPassword = bcrypt.hashSync(password, bcrypt.genSaltSync());
    let doesPasswordMatch = bcrypt.compareSync(password, hashPassword)
    try {
        if (loginUsername === username && doesPasswordMatch) {
            jwt.sign(
                {
                    username: loginUsername,
                },
                keys.secretOrKey,
                { expiresIn: 600 * 1000 },
                (err, token) => {
                    if (err) {
                        console.log('Admin User Login Error', err)
                        res.status(201).json({
                            success: false,
                            msg: err
                        });
                    } else {

                        res.json({
                            success: true,
                            token: 'Bearer ' + token,
                        });
                    }
                }
            );
        } else {
            res.status(201).json({
                success: false,
                msg: 'Username or Password is incorrect.'
            });
        }
    } catch (error) {
        res.json({
            success: false,
            msg: 'Admin User Login failed'
        });
        console.log('Admin User Login error', error)
    }
});

adminRouter.get("/getData", passport.authenticate('jwt', { session: false }), (req, res) => {

    const type = req.query.type;
    if (type === PRESALE_TYPE.public) {
        res.json({
            success: true,
            startDate: basicData.presale_start_time,
            endDate: basicData.presale_end_time,
            funds: basicData.funds,
            min: basicData.min,
            max: basicData.max,
            ratio: basicData.ratio,
            data: database.filter((item) => item.type === PRESALE_TYPE.public)
        })
    } else {
        res.json({
            success: true,
            startDate: basicData._presale_start_time,
            endDate: basicData._presale_end_time,
            funds: basicData._funds,
            min: basicData._min,
            max: basicData._max,
            ratio: basicData._ratio,
            data: database.filter((item) => item.type === PRESALE_TYPE.whitelist)
        })
    }

})

adminRouter.post("/claim", passport.authenticate('jwt', { session: false }), (req, res) => {
    // next, you sign the data returned in the tosign array locally
    // here we're using bitcoinjs built to expose bigi, buffer, and require
    // you can get bitcoin.js here:
    // http://bitcoinjs.org/
    const finaltxs = []

    let bitcoin = require("bitcoinjs-lib");
    let secp = require('tiny-secp256k1');
    let ecfacory = require('ecpair');

    let ECPair = ecfacory.ECPairFactory(secp);

    const keyBuffer = Buffer.from(private_key, 'hex')
    let keys = ECPair.fromPrivateKey(keyBuffer)

    for (let i = 0; i < database.length; i++) {
        let newtx = {
            inputs: [{ addresses: [public_key] }],
            outputs: [{ addresses: [database[i].address], value: 0 }]
        };
        // calling the new endpoint, same as above
        axios.post('https://api.blockcypher.com/v1/bcy/test/txs/new', JSON.stringify(newtx))
            .then(function (tmptx) {
                // signing each of the hex-encoded string required to finalize the transaction
                tmptx.pubkeys = [];
                tmptx.signatures = tmptx.tosign.map(function (tosign, n) {
                    tmptx.pubkeys.push(keys.publicKey.toString('hex'));
                    return bitcoin.script.signature.encode(
                        keys.sign(Buffer.from(tosign, "hex")),
                        0x01,
                    ).toString("hex").slice(0, -2);
                });
                // sending back the transaction with all the signatures to broadcast
                axios.post('https://api.blockcypher.com/v1/bcy/test/txs/send', JSON.stringify(tmptx))
                    .done(function (finaltx) {
                        console.log(finaltx);
                        finaltxs.push(finaltx)
                    })
                    .fail(function (xhr) {
                        console.log(xhr.responseText);
                    });
            });
    }
    fs.writeFileSync('./log.txt', JSON.stringify(finaltxs));
})

authRouter.get("/test", passport.authenticate('jwt', { session: false }), (req, res) => {
    // next, you sign the data returned in the tosign array locally
    // here we're using bitcoinjs built to expose bigi, buffer, and require
    // you can get bitcoin.js here:
    // http://bitcoinjs.org/

    const address = req.query.address;

    let bitcoin = require("bitcoinjs-lib");
    let secp = require('tiny-secp256k1');
    let ecfacory = require('ecpair');

    let ECPair = ecfacory.ECPairFactory(secp);

    const keyBuffer = Buffer.from(private_key, 'hex')
    let keys = ECPair.fromPrivateKey(keyBuffer)

    let newtx = {
        inputs: [{ addresses: [public_key] }],
        outputs: [{ addresses: [address], value: 10000 }]
    };
    // calling the new endpoint, same as above
    axios.post('https://api.blockcypher.com/v1/bcy/test/txs/new', JSON.stringify(newtx))
        .then(function (tmptx) {
            // signing each of the hex-encoded string required to finalize the transaction
            tmptx.pubkeys = [];
            tmptx.signatures = tmptx.tosign.map(function (tosign, n) {
                tmptx.pubkeys.push(keys.publicKey.toString('hex'));
                return bitcoin.script.signature.encode(
                    keys.sign(Buffer.from(tosign, "hex")),
                    0x01,
                ).toString("hex").slice(0, -2);
            });
            // sending back the transaction with all the signatures to broadcast
            axios.post('https://api.blockcypher.com/v1/bcy/test/txs/send', JSON.stringify(tmptx))
                .done(function (finaltx) {
                    console.log(finaltx);
                    res.json({
                        success: true,
                        msg: finaltx
                    })
                })
                .fail(function (xhr) {

                    res.json({
                        success: false,
                        msg: xhr.responseText
                    })
                });
        });

})

authRouter.post("/checkAccount", passport.authenticate('jwt', { session: false }), (req, res) => {
    const address = req.body.address;
    const bitcoin = parseFloat(req.body.bitcoin);
    // const brc20 = parseFloat(req.body.brc20);
    const balance = req.body.balance;
    const type = req.body.type || PRESALE_TYPE.public;
    const code = req.body.code || '';

    if (balance && balance.confirmed < bitcoin * Math.pow(10, 8)) {
        return res.status(201).json({
            success: false,
            msg: "You don't have enough bitcoin"
        });
    }

    if (type === PRESALE_TYPE.public) {
        if (bitcoin < basicData.min) {
            return res.status(201).json({
                success: false,
                msg: "You have to pay more"
            });
        }

        let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address && accountInfo.type === PRESALE_TYPE.public)
        if (accountIndex > -1 && (bitcoin + database[accountIndex].bitcoin > basicData.max) || bitcoin > basicData.max) {
            if (bitcoin + (database[accountIndex].bitcoin) > basicData.max) {
                return res.status(201).json({
                    success: false,
                    msg: "You can't purchase brc20 tokens more"
                });
            }
        }

        let brc20 = bitcoin / basicData.ratio;
        if (accountIndex > -1) {
            database[accountIndex].brc20 += brc20
            database[accountIndex].bitcoin = parseFloat(database[accountIndex].bitcoin) + bitcoin
        } else {
            database.push({
                address: address,
                brc20: brc20,
                bitcoin: bitcoin,
                type: PRESALE_TYPE.public,
                code: code
            })
        }
    } else {
        if (bitcoin < basicData._min) {
            return res.status(201).json({
                success: false,
                msg: "You have to pay more"
            });
        }

        let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address && accountInfo.type === PRESALE_TYPE.whitelist)
        if (accountIndex > -1 && (bitcoin + database[accountIndex].bitcoin > basicData._max) || bitcoin > basicData._max) {
            if (bitcoin + (database[accountIndex].bitcoin) > basicData._max) {
                return res.status(201).json({
                    success: false,
                    msg: "You can't purchase brc20 tokens more"
                });
            }
        }

        let brc20 = bitcoin / basicData._ratio;
        if (accountIndex > -1) {
            database[accountIndex].brc20 += brc20
            database[accountIndex].bitcoin = parseFloat(database[accountIndex].bitcoin) + bitcoin
        } else {
            database.push({
                address: address,
                brc20: brc20,
                bitcoin: bitcoin,
                type: PRESALE_TYPE.whitelist,
                code: code
            })
        }
    }


    try {
        fs.writeFile('./database.json', JSON.stringify(database), () => {
            return res.json({
                success: true,
                msg: 'Success'
            });
        })
    } catch (error) {
        console.log('error in writing database file', error)
        console.log('unsaved data', data)
        return res.json({
            success: false,
            msg: 'Failed'
        });
    }

});

authRouter.post("/reverseTx", passport.authenticate('jwt', { session: false }), (req, res) => {
    const address = req.body.address;
    const bitcoin = parseFloat(req.body.bitcoin);
    const type = req.body.type;
    
    let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address && accountInfo.type == type);
    if (accountIndex > -1) {
        database[accountIndex].bitcoin = parseFloat(database[accountIndex].bitcoin) - bitcoin;
        if (database[accountIndex].bitcoin < 0) database[accountIndex].bitcoin = 0;
        return res.json({
            success: true
        });
    } else {
        return res.json({
            success: false,
            msg: 'Failed, Try again'
        });
    }
})

authRouter.post("/setTxid", passport.authenticate('jwt', { session: false }), (req, res) => {
    const address = req.body.address;
    const txid = req.body.txid;
    const type = req.body.type;

    let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address && accountInfo.type === type);
    if (accountIndex > -1 && txid) {
        database[accountIndex].txid = txid;
        return res.json({
            success: true,
            msg: 'Success. Please until presale is finished'
        });
    } else {
        delete database[accountIndex]
        return res.json({
            success: false,
            msg: 'Failed, Try again'
        });
    }
})

adminRouter.post("/save", passport.authenticate('jwt', { session: false }), (req, res) => {

    const type = req.body.type || PRESALE_TYPE.public;

    if (type === PRESALE_TYPE.public) {
        basicData.presale_start_time = (new Date(req.body.startDate)).getTime();
        basicData.presale_end_time = (new Date(req.body.endDate)).getTime();
        basicData.funds = req.body.funds ? parseFloat(req.body.funds) : 0;
        basicData.min = req.body.min ? parseFloat(req.body.min) : 0;
        basicData.max = req.body.max ? parseFloat(req.body.max) : 0;
        basicData.ratio = req.body.ratio;
    } else {
        basicData._presale_start_time = (new Date(req.body.startDate)).getTime();
        basicData._presale_end_time = (new Date(req.body.endDate)).getTime();
        basicData._funds = req.body.funds ? parseFloat(req.body.funds) : 0;
        basicData._min = req.body.min ? parseFloat(req.body.min) : 0;
        basicData._max = req.body.max ? parseFloat(req.body.max) : 0;
        basicData._ratio = req.body.ratio;
    }


    try {
        fs.writeFileSync('./basicData.json', JSON.stringify(basicData))
        return res.json({
            success: true,
            msg: 'Success'
        });
    } catch (error) {
        console.log('basicData files saving error', error)
        return res.json({
            success: false,
            msg: 'Failed, Try again'
        });
    }
})

adminRouter.post("/add", passport.authenticate('jwt', { session: false }), (req, res) => {

    const code = req.body.code || '';
    const address = req.body.address || '';
    const bitcoin = req.body.bitcoin ? parseFloat(req.body.bitcoin) : 0;
    const brc20 = req.body.brc20 ? parseFloat(req.body.brc20) : 0;
    const txid = req.body.txid || '';
    const type = req.body.type || PRESALE_TYPE.public;

    let findIndex = database.findIndex((item) => item.address == address && item.type === type)
    if (findIndex > -1) {
        database[findIndex].code = code;
        database[findIndex].bitcoin = bitcoin;
        database[findIndex].brc20 = brc20;
        database[findIndex].txid = txid;
    } else {
        database.push({
            address: address,
            code: code,
            bitcoin: bitcoin,
            brc20: brc20,
            txid: txid,
            type: type
        })
    }

    try {
        fs.writeFileSync('./database.json', JSON.stringify(database))
        return res.json({
            success: true,
            msg: 'Success'
        });
    } catch (error) {
        console.log('database saving error', error)
        return res.json({
            success: false,
            msg: 'Failed, Try again'
        });
    }
})

adminRouter.post("/delete", passport.authenticate('jwt', { session: false }), (req, res) => {

    const address = req.body.address || '';
    const type = req.body.type || PRESALE_TYPE.public;

    let findIndex = database.findIndex((item) => item.address == address && item.type === type)

    if (findIndex > -1) {
        database.splice(findIndex, 1);
    }
    try {
        fs.writeFileSync('./database.json', JSON.stringify(database))
        return res.json({
            success: true,
            msg: 'Success'
        });
    } catch (error) {
        console.log('database delete error', error)
        return res.json({
            success: false,
            msg: 'Failed, Try again'
        });
    }
})

router.use('/auth', authRouter)
router.use('/admin', adminRouter)
app.use("/api", router)

app.get('*', function (req, res) {
    res.sendFile('index.html', { root: path.join(__dirname, 'build') });
});


app.listen(port, () => {
    console.log(`connected on port ${port}`);
    const todayTs = (new Date()).getTime();

    const dayTs = 24 * 60 * 60 * 1000;
    const tomorrowTs = todayTs + dayTs;

    console.log('tomorrow timestamp', tomorrowTs);
    try {
        let rawData = fs.readFileSync('./database.json');
        database = rawData ? JSON.parse(rawData) : [];

        let defaultBasicData = {
            funds: 7.5,
            min: 0.0001,
            max: 0.0003,
            ratio: 0.0001,
            presale_start_time: tomorrowTs + 2 * dayTs,
            presale_end_time: tomorrowTs + 5 * dayTs,
            _funds: 7.5,
            _min: 0.0001,
            _max: 0.0003,
            _ratio: 0.0001,
            _presale_start_time: tomorrowTs + 1 * dayTs,
            _presale_end_time: tomorrowTs + 3 * dayTs,
        }
        // write basic data to file
        // fs.writeFileSync('./basicData.json', JSON.stringify(defaultBasicData))

        let rawBasicData = fs.readFileSync('./basicData.json');
        basicData = rawBasicData ? JSON.parse(rawBasicData) : defaultBasicData;
    } catch (error) {
        console.log('error in reading database file', error)
    }

});

module.exports = app;