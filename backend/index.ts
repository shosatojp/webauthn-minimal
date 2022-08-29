import { ExpectedAssertionResult, ExpectedAttestationResult, Fido2Lib } from 'fido2-lib';
import session from 'express-session';
import { body, validationResult } from 'express-validator';
import express from 'express';

const db = new Map<string, { id: Uint8Array, publickey: string }>();
const ORIGIN = 'https://webauthn.shosato.jp';
const RPID = 'webauthn.shosato.jp';
const RPNAME = 'test-auth-server';

const VALIDATORS = {
    email: body('email').isEmail(),
    message: body('message').isString(),
    password: body('password').isString().isLength({ min: 8, max: 256 }),
};

const uint8ArrayEqual = (a: Uint8Array, b: Uint8Array) => {
    return a.length === b.length && a.every((v, i) => v === b[i]);
};


/**
 * setup fido2lib
 */
const f2l = new Fido2Lib({
    timeout: 60000,
    rpId: RPID,
    rpName: RPNAME,
    challengeSize: 128,
    attestation: "direct",
    cryptoParams: [-7, -257],
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: false,
    authenticatorUserVerification: "discouraged"
});


const app = express();
app.use(express.json({ type: 'json' }));
app.use('/', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});

app.use('/', session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 },
}));

app.post('/pre-attestation',
    VALIDATORS.email,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const email: string = req.body.email;
            const registrationOptionsRaw = await f2l.attestationOptions();
            const registrationOptions = {
                ...registrationOptionsRaw,
                user: {
                    id: Buffer.from(new Uint8Array(16)).toString('base64'),
                    name: email,
                    displayName: email,
                },
                challenge: Buffer.from(registrationOptionsRaw.challenge).toString('base64'),
            };

            (req.session as any)['registrationOptions'] = registrationOptions;

            return res.status(200).json(registrationOptions);
        } catch (error) {
            console.error(error);
            return res.status(500).json({ error: '' });
        }
    });

app.post('/attestation',
    VALIDATORS.email,
    body('rawId').isBase64(),
    body('response.clientDataJSON').isBase64(),
    body('response.attestationObject').isBase64(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            if (!(req.session as any)['registrationOptions']) {
                console.error("failed");
                return res.status(200).json({});
            }

            const email: string = req.body.email;
            const challenge: string = (req.session as any)['registrationOptions'].challenge;

            const attestationExpectations = {
                challenge: Buffer.from(challenge, 'base64').toString('base64url'),
                origin: ORIGIN,
                factor: "either"
            } as ExpectedAttestationResult;
            const regResult = await f2l.attestationResult({
                rawId: new Uint8Array(Buffer.from(req.body.rawId, 'base64')).buffer,
                response: {
                    clientDataJSON: Buffer.from(req.body.response.clientDataJSON, 'base64').toString('base64url'),
                    attestationObject: Buffer.from(req.body.response.attestationObject, 'base64').toString('base64url'),
                },
            }, attestationExpectations);

            db.set(email, {
                id: new Uint8Array(regResult.authnrData.get('credId')),
                publickey: regResult.authnrData.get('credentialPublicKeyPem'),
            });
            return res.status(200).json({});
        } catch (error) {
            console.error(error);
            return res.status(500).json({ error: 'failed to create user' });
        }
    });

app.post('/pre-authenticate',
    VALIDATORS.email,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const email: string = req.body.email;
            if (!db.has(email)) {
                throw new Error('user not found');
            }
            const keys = [db.get(email)!];
            const authnOptionsRaw = await f2l.assertionOptions();
            const authnOptions = {
                ...authnOptionsRaw,
                challenge: Buffer.from(authnOptionsRaw.challenge).toString('base64'),
                allowCredentials: keys.map(key => ({
                    transports: ['internal'],
                    type: 'public-key',
                    id: Buffer.from(key.id).toString('base64'),
                })),
            };

            (req.session as any)['authnOptions'] = authnOptions;

            return res.status(200).json(authnOptions);
        } catch (error) {
            console.error(error);
            return res.status(500).json({});
        }
    });

app.post('/authenticate',
    VALIDATORS.email,
    body('rawId').isBase64(),
    body('response.clientDataJSON').isBase64(),
    body('response.authenticatorData').isBase64(),
    body('response.signature').isBase64(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            if (!(req.session as any)['authnOptions']) {
                console.error("failed");
                return res.status(200).json({});
            }

            const email: string = req.body.email;
            if (!db.has(email)) {
                throw new Error('user not found');
            }
            const keyid = new Uint8Array(Buffer.from(req.body.rawId, 'base64'));
            const key = [db.get(email)!].find(e => uint8ArrayEqual(e.id, keyid));
            if (!key) {
                throw new Error("no key found");
            }

            const challenge = (req.session as any)['authnOptions'].challenge;
            const attestationExpectations = {
                challenge: Buffer.from(challenge, 'base64').toString('base64url'),
                origin: ORIGIN,
                factor: "either",
                publicKey: key.publickey,
                prevCounter: 0, // 現在のcounterよりも小さければ良い
                userHandle: null,
            } as ExpectedAssertionResult;
            await f2l.assertionResult({
                rawId: key.id.buffer,
                response: {
                    clientDataJSON: Buffer.from(req.body.response.clientDataJSON, 'base64').toString('base64url'),
                    authenticatorData: new Uint8Array(Buffer.from(req.body.response.authenticatorData, 'base64')).buffer,
                    signature: Buffer.from(req.body.response.signature, 'base64').toString('base64url'),
                },
            }, attestationExpectations);

            // authorized

            return res.status(200).json({});
        } catch (error) {
            console.error(error);
            return res.status(500).json({});
        }
    });


app.use('/', express.static('../frontend/dist', {
    cacheControl: true,
}));
app.set('trust proxy', 1);
app.listen(
    3000, '0.0.0.0',
    () => {
        console.log(`server started`);
    });
