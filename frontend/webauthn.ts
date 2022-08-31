import base64js from 'base64-js';

export class WebAuthnClient {
    host: string;

    constructor(host: string) {
        this.host = host;
    }

    async webAuthnAttestaion(email: string, code: string | undefined = undefined) {
        if (!(typeof email === 'string'
            && (typeof code === 'string' || code === undefined))) {
            throw new Error('invalid input');
        }

        const res = await fetch(this.host + '/pre-attestation', {
            method: 'post',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code }),
        });
        let options = await res.json();
        if (res.status !== 200) {
            console.error(options);
            throw new Error();
        }
        const publicKey = {
            ...options,
            challenge: base64js.toByteArray(options.challenge),
            user: {
                ...options.user,
                id: base64js.toByteArray(options.user.id),
            },
        };
        console.log(publicKey);
        const newCred: any = await navigator.credentials.create({ publicKey });
        console.log(newCred);
        const resAttestaion = await fetch(this.host + '/attestation', {
            method: 'post',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                code,
                id: newCred.id,
                rawId: base64js.fromByteArray(new Uint8Array(newCred.rawId)),
                response: {
                    attestationObject: base64js.fromByteArray(new Uint8Array(newCred.response.attestationObject)),
                    clientDataJSON: base64js.fromByteArray(new Uint8Array(newCred.response.clientDataJSON)),
                }
            }),
        });
        const result = await resAttestaion.json();
        if (resAttestaion.status !== 200) {
            console.error(result);
            throw new Error();
        }
        return result;
    }

    async webAuthnAuthenticate(email: string, code: boolean = false) {
        if (typeof email !== 'string' || typeof code !== 'boolean') {
            throw new Error('invalid input');
        }

        const res = await fetch(this.host + '/pre-authenticate', {
            method: 'post',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });
        let options = await res.json();
        if (res.status !== 200) {
            console.error(options);
            throw new Error();
        }
        const publicKey = {
            ...options,
            challenge: base64js.toByteArray(options.challenge),
            allowCredentials: options.allowCredentials.map((e: any) => {
                e.id = base64js.toByteArray(e.id);
                return e;
            }),
        };

        console.log(publicKey);
        const cred: any = await navigator.credentials.get({ publicKey });
        console.log(cred);
        const resAuthenticate = await fetch(this.host + '/authenticate', {
            method: 'post',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                code,
                id: cred.id,
                rawId: base64js.fromByteArray(new Uint8Array(cred.rawId)),
                response: {
                    authenticatorData: base64js.fromByteArray(new Uint8Array(cred.response.authenticatorData)),
                    signature: base64js.fromByteArray(new Uint8Array(cred.response.signature)),
                    clientDataJSON: base64js.fromByteArray(new Uint8Array(cred.response.clientDataJSON)),
                },
            }),
        });

        const tokens = await resAuthenticate.json();
        if (resAuthenticate.status !== 200) {
            console.error(tokens);
            throw new Error();
        }
        return tokens;
    }
}
