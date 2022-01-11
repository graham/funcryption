import * as fernet from 'fernet';

// This is a fn so that it can be stubbed out during testing.
let gen_iv = () => {
    return [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
}

class Service {
    inner_secret: fernet.Secret;
    outer_secret: fernet.Secret;
    iv_fn: () => Array<number>;
    
    constructor(inner_secret:fernet.Secret, outer_secret:fernet.Secret) {
        this.inner_secret = inner_secret;
        this.outer_secret = outer_secret;
        this.iv_fn = gen_iv;
    }

    gen_magic(claims: Array<string>, for_service:string): string {
        let token = new fernet.Token({
            secret: this.inner_secret,
            time: new Date(),
            iv: this.iv_fn(),
        });

        return token.encode(JSON.stringify({
            claims: claims,
            service: for_service,
        }));        
    }

    decode_payload(token: string): any {
        let outer_token: fernet.Token = new fernet.Token({
            secret: this.outer_secret,
            token: token,
            ttl:0,
        });

        let encrypted_magic = outer_token.decode();

        let inner_token: fernet.Token = new fernet.Token({
            secret: this.inner_secret,
            token: encrypted_magic,
            ttl:0,
        });

        return JSON.parse(inner_token.decode());
    }
}

class Client {
    secret: fernet.Secret;
    magic: string;    
    iv_fn: () => Array<number>;
    
    constructor(secret: fernet.Secret, magic: string) {
        this.secret = secret;
        this.magic = magic;
        this.iv_fn = gen_iv;
    }

    gen_api_token(): string {
        let value_token: fernet.Token = new fernet.Token({
            secret: this.secret,
            time: new Date(),
            iv: this.iv_fn(),
        });
        return value_token.encode(this.magic);
    }
}


