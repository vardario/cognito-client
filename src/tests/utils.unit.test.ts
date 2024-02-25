import { expect, test, describe } from 'vitest';
import {
  calculateHKDF,
  calculateS,
  calculateSecretHash,
  calculateSignature,
  calculateU,
  formatTimestamp,
  generateA,
  getPasswordAuthenticationKey,
  hashBuffer,
  hashHexString,
  padHex
} from '../utils';
import { BigInteger } from 'jsbn';

describe('Utils Test', () => {
  test('padHex', () => {
    expect(padHex(new BigInteger('15'))).toBe('0f');
    expect(padHex(new BigInteger('4095'))).toBe('0fff');
    expect(padHex(new BigInteger('310'))).toBe('0136');
  });

  test('hashHexString', async () => {
    expect(await hashHexString('ff')).toBe('a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89');
    expect(await hashHexString('0123')).toBe('b71de80778f2783383f5d5a3028af84eab2f18a4eb38968172ca41724dd4b3f4');
  });

  test('hashBuffer', async () => {
    expect(await hashBuffer(new Uint8Array([0xff]))).toBe(
      'a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89'
    );
    expect(await hashBuffer(new Uint8Array([0x01, 0x23]))).toBe(
      'b71de80778f2783383f5d5a3028af84eab2f18a4eb38968172ca41724dd4b3f4'
    );
  });

  test('generateA', () => {
    const smallA = generateA(new BigInteger('100'));
    expect(smallA.toString()).toBe('1267650600228229401496703205376');
  });

  test('calculateU', async () => {
    const u = await calculateU(new BigInteger('100'), new BigInteger('100'));
    expect(u.toString()).toBe('70332525207219800455006367509018178659670313831872967035717895932648085979283');
  });

  test('calculateS', () => {
    const s = calculateS(new BigInteger('1'), new BigInteger('2'), new BigInteger('3'), new BigInteger('4'));
    expect(s.toString()).toBe(
      '5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394108737997185958750117096328186113285098758916641740918046753154406248552338830082056866591606088156608060604806971832549807299296123083069198694203128583316840534100262020920889026655577536636750554173250262994749697781980080849048403117385617721960451075788245889547715737308326318533063595451531962857067337193523476927933149520515933129751886387804976202728442059217742807994802054816532741174549772492321716914349968002961476349298833293205498460336244805117689992229628920310354519723549636852605179355221038194957586812051333018343807'
    );
  });

  test('calculateHKDF', async () => {
    const hkdf = await calculateHKDF(new Uint8Array([0xff]), new Uint8Array([0x0f]));
    expect(hkdf).toStrictEqual(new Uint8Array([7, 216, 173, 67, 93, 105, 60, 42, 9, 224, 149, 241, 59, 180, 156, 79]));
  });

  test('getPasswordAuthenticationKey', async () => {
    const key = await getPasswordAuthenticationKey(
      'userPoolName',
      'user',
      'password',
      new BigInteger('1'),
      new BigInteger('2'),
      new BigInteger('3'),
      new BigInteger('4')
    );

    expect(key).toStrictEqual(
      new Uint8Array([86, 45, 9, 114, 105, 206, 19, 253, 169, 180, 204, 213, 65, 178, 79, 134])
    );
  });

  test('calculateSignature', async () => {
    const hkdf = await calculateHKDF(new Uint8Array([0xff]), new Uint8Array([0x0f]));
    const { signature, timeStamp } = await calculateSignature(
      'userPoolName',
      '434a1100-258c-488c-a9a9-b00ef4be2713',
      'secret',
      hkdf,
      new Date(Date.UTC(2023))
    );

    expect(signature).toBe('1czEVajO/2LR45cGBZx133pQUJcRi31jHln4U6WRROA=');
    expect(timeStamp).toBe('Sun Jan 1 00:00:00 UTC 2023');
  });

  test('formatTimestamp', () => {
    expect(formatTimestamp(new Date(Date.UTC(2023)))).toBe('Sun Jan 1 00:00:00 UTC 2023');
  });

  test('calculateSecretHash', async () => {
    const hash = await calculateSecretHash('clientSecret', 'clientId', 'username');
    expect(hash).toBe('vH5prJR/bHEh4xqtNXGUBICLyh4AkiNCkefVf8h3VHs=');
  });
});
