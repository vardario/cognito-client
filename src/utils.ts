import * as bigIntMath from './bigint-math.js';

const WEEK_DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function uint8ArrayFromHexString(hexString: string) {
  return Uint8Array.from(hexString.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
}

export function uint8ArrayFromString(str: string) {
  const textEncoder = new TextEncoder();
  return textEncoder.encode(str);
}

export function uint8ArrayFromBase64String(str: string) {
  const binaryString = atob(str);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export function uint8ArrayToHexString(bytes: Uint8Array) {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

export function uint8ArrayToBase64String(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes));
}

const N = BigInt(
  '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
);

const g = BigInt('0x2');
const k = BigInt('0x' + (await hashHexString(`${padHex(N)}${padHex(g)}`)));

export function padHex(bigInt: bigint): string {
  const HEX_MSB_REGEX = /^[89a-f]/i;
  const isNegative = bigInt < 0n;

  let hexStr = bigIntMath.abs(bigInt).toString(16);
  hexStr = hexStr.length % 2 !== 0 ? `0${hexStr}` : hexStr;
  hexStr = HEX_MSB_REGEX.test(hexStr) ? `00${hexStr}` : hexStr;

  if (isNegative) {
    const invertedNibbles = hexStr
      .split('')
      .map(x => {
        const invertedNibble = ~parseInt(x, 16) & 0xf;
        return '0123456789ABCDEF'.charAt(invertedNibble);
      })
      .join('');

    const flippedBitsBI = BigInt('0x' + invertedNibbles) + 1n;
    hexStr = flippedBitsBI.toString(16);

    if (hexStr.toUpperCase().startsWith('FF8')) {
      hexStr = hexStr.substring(2);
    }
  }

  return hexStr;
}

export async function hashHexString(str: string) {
  return hashBuffer(uint8ArrayFromHexString(str));
}

export async function hashBuffer(buffer: Uint8Array) {
  const hashArray = await digest('SHA-256', buffer);
  return uint8ArrayToHexString(hashArray);
}

export async function generateSmallA() {
  return BigInt('0x' + (await randomBytes(128)).toString('hex'));
}

export function generateA(smallA: bigint) {
  const A = bigIntMath.modPow(g, smallA, N);
  return A;
}

export async function calculateU(A: bigint, B: bigint) {
  return BigInt('0x' + (await hashHexString(padHex(A) + padHex(B))));
}

export function calculateS(X: bigint, B: bigint, U: bigint, smallA: bigint) {
  const gModPowXN = bigIntMath.modPow(g, X, N);
  const bMinusKMult = B - k * gModPowXN;
  return bigIntMath.modPow(bMinusKMult, smallA + U * X, N) % N;
}

export async function calculateHKDF(ikm: Uint8Array, salt: Uint8Array) {
  const infoBitsBuffer = new Uint8Array([
    ...uint8ArrayFromString('Caldera Derived Key'),
    ...uint8ArrayFromString(String.fromCharCode(1))
  ]);

  const prk = await hmac('SHA-256', salt, ikm);
  const hmacResult = await hmac('SHA-256', prk, infoBitsBuffer);

  return hmacResult.slice(0, 16);
}

export async function getPasswordAuthenticationKey(
  poolName: string,
  username: string,
  password: string,
  B: bigint,
  U: bigint,
  smallA: bigint,
  salt: bigint
) {
  const usernamePassword = `${poolName}${username}:${password}`;
  const usernamePasswordHash = await hashBuffer(uint8ArrayFromString(usernamePassword));
  const X = BigInt('0x' + (await hashHexString(padHex(salt) + usernamePasswordHash)));
  const S = calculateS(X, B, U, smallA);

  return calculateHKDF(uint8ArrayFromHexString(padHex(S)), uint8ArrayFromHexString(padHex(U)));
}

export async function calculateSignature(
  poolName: string,
  userId: string,
  secretBlock: string,
  hkdf: Uint8Array,
  date = new Date()
) {
  const timeStamp = formatTimestamp(date);

  const concatBuffer = new Uint8Array([
    ...uint8ArrayFromString(poolName),
    ...uint8ArrayFromString(userId),
    ...uint8ArrayFromBase64String(secretBlock),
    ...uint8ArrayFromString(timeStamp)
  ]);

  const signature = uint8ArrayToBase64String(await hmac('SHA-256', hkdf, concatBuffer));

  return {
    signature,
    timeStamp
  };
}

export function decodeJwt<T = unknown>(jwt: string) {
  const [header, payload, signature] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(header, 'base64').toString('utf-8')),
    payload: JSON.parse(Buffer.from(payload, 'base64').toString('utf-8')) as T,
    signature: signature
  };
}

export async function randomBytes(num: number) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(num)));
}

export function formatTimestamp(date: Date) {
  return `${WEEK_DAYS[date.getUTCDay()]} ${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()} ${date
    .getUTCHours()
    .toString()
    .padStart(2, '0')}:${date.getUTCMinutes().toString().padStart(2, '0')}:${date
    .getUTCSeconds()
    .toString()
    .padStart(2, '0')} UTC ${date.getUTCFullYear()}`;
}

export async function calculateSecretHash(clientSecret: string, userPoolClientId: string, username: string) {
  const message = `${username}${userPoolClientId}`;
  const hash = uint8ArrayToBase64String(
    await hmac('SHA-256', uint8ArrayFromString(clientSecret), uint8ArrayFromString(message))
  );

  return hash;
}

export async function digest(algorithm: AlgorithmIdentifier, data: Uint8Array) {
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return new Uint8Array(hashBuffer);
}

export async function hmac(algorithm: AlgorithmIdentifier, key: Uint8Array, data: Uint8Array) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'HMAC',
      hash: algorithm
    },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(signature);
}
