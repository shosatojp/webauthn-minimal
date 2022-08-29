import { WebAuthnClient } from './webauthn';

const host = 'https://webauthn.shosato.jp';
const client = new WebAuthnClient(host);

document.addEventListener('DOMContentLoaded', () => {
    /**
     * webauthn
     */
    document.querySelector('#register')!.addEventListener('click', async () => {
        const email = (document.querySelector('#email')! as HTMLInputElement).value;
        const result = await client.webAuthnAttestaion(email);
        console.log('successfully registered! 🚀', result);
    });

    document.querySelector('#authenticate')!.addEventListener('click', async () => {
        const email = (document.querySelector('#email')! as HTMLInputElement).value;
        const tokens = await client.webAuthnAuthenticate(email);

        console.log('successfully authenticated! 🙆🏻', tokens);
        localStorage.setItem('token', JSON.stringify(tokens.token));
        localStorage.setItem('refreshToken', JSON.stringify(tokens.refreshToken));
    });

    /**
     * log
     */
    {
        const logElement = document.querySelector('#log')!;
        (console as any)._log = console.log;
        (console as any)._error = console.error;

        console.log = (...data) => {
            const e = document.createElement('div');
            e.textContent = JSON.stringify(data);
            logElement.appendChild(e);

            (console as any)._log(...data);
        }
        console.error = (...data) => {
            const e = document.createElement('div');
            e.textContent = JSON.stringify(data);
            e.style.color = 'red';
            logElement.appendChild(e);

            (console as any)._error(...data);
        }
    }
});
