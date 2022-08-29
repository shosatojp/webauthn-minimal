# WebAuthn Minimal Server

## Get started

```sh
git clone https://github.com/shosatojp/webauthn-minimal.git
cd webauthn-minimal
```

modify `webauthn.shosato.jp` to your domain.

```sh
# install dependencies
npm ci

# build example fontend
npm build

# start auth server
npm start
```

## Docker

```
docker-compose up --build
```

## Files

### Frontend

- `public/`
- `dist/` (generated)
- `webpack.config.js`

### Backend

- `src/`
