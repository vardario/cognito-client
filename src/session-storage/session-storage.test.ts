import { randomBytes } from "crypto";
import { CognitoClient, Session } from "../cognito-client.js";
import { setupCognito, setupJsDom, user } from "../test-utils.js";
import { MemorySessionStorage } from "./memory-session-storage.js";
import { expect, test, describe, beforeAll, afterAll } from "vitest";
import { GenericContainer, StartedTestContainer } from "testcontainers";
import { CookieSessionStorage } from "./cookie-session-storage.js";

describe("SessionStorage", () => {
  setupJsDom();

  let cognitoClient: CognitoClient;
  let container: StartedTestContainer;
  let session: Session;

  beforeAll(async () => {
    const cognitoPort = 9229;
    container = await new GenericContainer("jagregory/cognito-local")
      .withExposedPorts(cognitoPort)
      .start();
    const cognitoEndpoint = `http://localhost:${container.getMappedPort(
      cognitoPort
    )}`;

    const userPoolConfig = await setupCognito(cognitoEndpoint);

    cognitoClient = new CognitoClient({
      userPoolId: userPoolConfig.userPoolId,
      userPoolClientId: userPoolConfig.userPoolClientId,
      endpoint: cognitoEndpoint,
    });

    session = await cognitoClient.authenticateUser(user.email, user.password);
  });

  afterAll(async () => {
    await container.stop();
  });

  test("MemorySessionStorage", async () => {
    const memorySessionStorage = new MemorySessionStorage(cognitoClient);
    memorySessionStorage.setSession(session);
    const expectedSession = await memorySessionStorage.getSession();
    expect(expectedSession).toBe(session);

    memorySessionStorage.setSession(undefined);

    expect(await memorySessionStorage.getSession()).toBeUndefined();
  });

  test("CookieSessionStorage", async () => {
    const cookieSessionStorage = new CookieSessionStorage(cognitoClient, {
      cookieName: "session",
    });
    cookieSessionStorage.setSession(session);
    const expectedSession = await cookieSessionStorage.getSession();
    expect(expectedSession).toStrictEqual(session);

    cookieSessionStorage.setSession(undefined);
    expect(await cookieSessionStorage.getSession()).toBeUndefined();
  });
});
