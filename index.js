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

dotenv.config()
const presale_account_address = process.env.PRESALE_ACCOUNT_ADDRESS

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

authRouter.post("/buyTokens", (req, res) => {
    const address = req.body.address;
    const bitcoin = req.body.bitcoin;
    const brc20 = req.body.brc20;
    

    return res.status(200).send({ response: presale_account_address });
});

app.use("/api/auth", passport.authenticate('jwt', { session: false }), authRouter)
app.use("/api", router)

app.listen(port, () => {
    console.log(`connected on port ${port}`);
});

module.exports = app;