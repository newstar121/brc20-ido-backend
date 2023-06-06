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
let basicData;
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

router.get("/getData", (req, res) => {
    let address = req.query.address;
    try {
        let data = {
            total: 0,
            contributor: 0,
            raisingPercentage: 0,
            funds: 0,
            inverstment: 0,
            received: 0,
            ratio: 0,
            max: 0,
            min: 0,
        }

        database.forEach((item) => {
            data.total += item.bitcoin;
        });

        data.contributor = database.length;
        
        data.funds = basicData.funds;
        
        data.raisingPercentage = (data.total / data.funds * 100).toFixed(2) || 0;
        
        let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address)
        data.inverstment = accountIndex > -1 ? database[accountIndex].bitcoin || 0 : 0;

        data.received = accountIndex > -1 ? database[accountIndex].brc20 || 0 : 0;
        
        data.ratio = basicData.ratio;

        data.min = basicData.min;

        data.max = basicData.max;

        res.json({
            success: true,
            data: data 
        });
    } catch(error) {
        res.json({
            success: false,
            msg: 'Getting data failed'
        });
        console.log('getData error', error)
    }
});

authRouter.post("/checkAccount", (req, res) => {
    const address = req.body.address;
    const bitcoin = parseFloat(req.body.bitcoin);
    // const brc20 = parseFloat(req.body.brc20);
    const balance = req.body.balance;

    if (balance && balance.confirmed < bitcoin * Math.pow(10, 8)) {
        return res.status(201).json({
            success: false,
            msg: "You don't have enough bitcoin"
        });
    }

    if (bitcoin < basicData.min) {
        return res.status(201).json({
            success: false,
            msg: "You have to pay more"
        });
    }

    let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address)
    if (accountIndex > -1 && (bitcoin + database[accountIndex].bitcoin > basicData.max) || bitcoin > basicData.max) {
        if (bitcoin + parseFloat(database[accountIndex].bitcoin) > MAX) {
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
        })
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

authRouter.post("/reverseTx", (req, res) => {
    const address = req.body.address;
    const bitcoin = parseFloat(req.body.bitcoin);

    let accountIndex = database.findIndex((accountInfo) => accountInfo.address == address);
    if (accountIndex > -1) {
        database[accountIndex].bitcoin = parseFloat(database[accountIndex].bitcoin) - bitcoin;
        if(database[accountIndex].bitcoin < 0) database[accountIndex].bitcoin = 0;
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
        
        let defaultBasicData = {
            funds: 7.5,
            min: 0.0001,
            max: 0.0003,
            ratio: 0.0001
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