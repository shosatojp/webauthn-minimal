# WebAuthn Minimal Server

## Get started

#### 1. clone repository

```sh
git clone https://github.com/shosatojp/webauthn-minimal.git
cd webauthn-minimal
```

#### 2. modify `webauthn.shosato.jp` to your domain.
#### 3. build

```
docker-compose up --build
```

#### 4. deploy

- setup reverse proxy to pass requests to `127.0.0.1:3000` via your domain
