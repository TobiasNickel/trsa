export interface IKeyPair {
    privateKey: string;
    publicKey: string;
}

export interface IGenratateOptions {
    bits: number;
}

export declare function generateKeyPair (options: IGenratateOptions): IKeyPair;
export declare function sign (data: string, privateKey: string): string;
export declare function verify (data: string, signature: string, publicKey: string): boolean;
export declare function encrypt (data: string, publicKey: string): string;
export declare function decrypt (data: string, privateKey: string): string;
