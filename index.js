const express = require("express");
const app = express();
const port = 5005;
const cors = require("cors");
const passport = require("passport")
const passportJWT = require("passport-jwt");
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const keys = require("./keys")
const router = express.Router()
const authRouter = express.Router()
const jwt = require("jsonwebtoken")
const dotenv = require('dotenv')
const fs = require('fs');

dotenv.config()
const presale_account_address = process.env.PRESALE_ACCOUNT_ADDRESS
const MIN = parseFloat(process.env.MIN)
const MAX = parseFloat(process.env.MAX)
const PRESALE_TIME = process.env.PRESALE_TIME

let database = [];

app.use(express.static(__dirname));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(passport.initialize());

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: keys.secretOrKey
}, (jwtPayload, cb) => {
    return cb(null, jwtPayload.address)
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
                    address: presale_account_address
                });
            }
        }
    );
});

router.get("/getPresaleTime", (req, res) => {
    let currentTs = (new Date()).getTime();
    if (PRESALE_TIME <= currentTs) {
        res.json({
            success: false,
            msg: 'Presale ended'
        });
    } else {
        res.json({
            success: true,
            timestamp: (PRESALE_TIME - currentTs)
        });
    }
});

authRouter.post("/checkAccount", (req, res) => {
    const address = req.body.address;
    const bitcoin = req.body.bitcoin;
    const brc20 = parseFloat(req.body.brc20);
    const balance = req.body.balance;

    if (balance && balance.confirmed < bitcoin * Math.pow(10, 8)) {
        return res.status(201).json({
            success: false,
            msg: "You don't have enough bitcoin"
        });
    }

    if (brc20 < MIN) {
        return res.status(201).json({
            success: false,
            msg: "You have to purchase brc20 tokens more than " + MIN
        });
    }

    let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address)
    if (accountIndex > -1 && (brc20 + database[accountIndex].brc20 > MAX) || brc20 > MAX) {
        if (brc20 + database[accountIndex].brc20 > MAX) {
            return res.status(201).json({
                success: false,
                msg: "You can't purchase brc20 tokens more than " + MAX
            });
        }
    }

    if (accountIndex > -1) {
        database[accountIndex].brc20 += brc20
        database[accountIndex].bitcoin += bitcoin
    } else {
        database.push({
            address: address,
            brc20: brc20,
            bitcoin: bitcoin,
        })
    }

    try {
        fs.writeFileSync('./database.json', JSON.stringify(database))
    } catch (error) {
        console.log('error in writing database file', error)
    }

    return res.json({
        success: true,
        msg: 'Success'
    });

});

authRouter.post("/setTxid", (req, res) => {
    const address = req.body.address;
    const txid = req.body.txid;

    let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address);
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

app.use("/api/auth", passport.authenticate('jwt', { session: false }), authRouter)
app.use("/api", router)

app.listen(port, () => {
    console.log(`connected on port ${port}`);
    const todayTs = (new Date()).getTime();
    const tomorrowTs = todayTs + 24 * 60 * 60 * 1000;
    console.log('tomorrow timestamp', tomorrowTs);
    try {
        let rawData = fs.readFileSync('./database.json');
        database = rawData ? JSON.parse(rawData) : [];
    } catch (error) {
        console.log('error in reading database file', error)
    }

});

module.exports = app;