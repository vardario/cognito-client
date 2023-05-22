import "isomorphic-fetch";
import { GenericContainer, StartedTestContainer } from "testcontainers";
import {
  CognitoClient,
  CognitoIdentityProvider,
  OAuth2Props,
} from "./cognito-client.js";
import { MemorySessionStorage } from "./session-storage/index.js";
import { newUser, setupCognito, user } from "./test-utils.js";
import {
  expect,
  test,
  describe,
  beforeAll,
  beforeEach,
  afterAll,
} from "vitest";

describe("Cognito Client", () => {
  let cognitoClient: CognitoClient;
  let container: StartedTestContainer;
  let sessionStorage = new MemorySessionStorage();

  const oAuth2: OAuth2Props = {
    cognitoDomain: "http://localhost",
    redirectUrl: "http://localhost",
    responseType: "code",
    scopes: ["email openid"],
  };

  let userPoolConfig: { userPoolClientId: string; userPoolId: string } = {
    userPoolClientId: "",
    userPoolId: "",
  };

  beforeAll(async () => {
    const cognitoPort = 9229;
    container = await new GenericContainer("jagregory/cognito-local")
      .withExposedPorts(cognitoPort)
      .start();
    const cognitoEndpoint = `http://localhost:${container.getMappedPort(
      cognitoPort
    )}`;

    userPoolConfig = await setupCognito(cognitoEndpoint);

    cognitoClient = new CognitoClient({
      userPoolId: userPoolConfig.userPoolId,
      userPoolClientId: userPoolConfig.userPoolClientId,
      sessionStorage: sessionStorage,
      endpoint: cognitoEndpoint,
      oAuth2: oAuth2,
    });
  });

  beforeEach(async () => {
    try {
      await cognitoClient.signOut();
    } catch (error) {}
  });

  afterAll(async () => {
    await container.stop();
  });

  test("authenticateUser", async () => {
    const session = await cognitoClient.authenticateUser(
      user.email,
      user.password
    );
    expect(session).toEqual(await cognitoClient.getSession());

    //Simulate session expiring
    sessionStorage.setSession({
      ...session,
      expiresIn: 0,
    });

    const newSession = await cognitoClient.getSession();
    expect(newSession).not.toEqual(session);
  });

  test("authenticateUserSrp: TODO", async () => {
    // TODO: Currently SRP auth is not supported through cognito-local
    // const session = await cognitoClient.authenticateUserSrp(user.name, user.password);
    // expect(session).toEqual(await cognitoClient.getSession());
    expect(true).toBe(true);
  });

  test("signUp", async () => {
    const { id, confirmed } = await cognitoClient.signUp(
      newUser.email,
      newUser.password,
      [
        { Name: "givenName", Value: newUser.givenName },
        { Name: "familyName", Value: newUser.familyName },
      ]
    );
    expect(id).toBeDefined();
    expect(confirmed).toBe(false);
  });

  test("changePassword", async () => {
    const newPassword = "newPassword";
    expect(
      cognitoClient.changePassword(user.password, newPassword)
    ).rejects.toThrow();
    await cognitoClient.authenticateUser(user.email, user.password);
    await cognitoClient.changePassword(user.password, newPassword);
    await cognitoClient.signOut();
    expect(
      cognitoClient.authenticateUser(user.email, user.password)
    ).rejects.toThrow();
    await cognitoClient.authenticateUser(user.email, "newPassword");
  });
  test("generateOAuthSignInUrl", async () => {
    const _test = async (
      cb: (searchParams: URLSearchParams) => void,
      identityProvider?: CognitoIdentityProvider
    ) => {
      const hostedUIUrl = await cognitoClient.generateOAuthSignInUrl(
        identityProvider
      );
      const { searchParams } = new URL(hostedUIUrl);

      expect(searchParams.get("redirect_uri")).toBe(oAuth2.redirectUrl);
      expect(searchParams.get("response_type")).toBe(oAuth2.responseType);
      expect(searchParams.get("client_id")).toBe(
        userPoolConfig.userPoolClientId
      );
      expect(searchParams.get("scope")).toBe(oAuth2.scopes.join(" "));
      expect(searchParams.get("state")).toBeDefined();
      expect(searchParams.get("code_challenge")).toBeDefined();
      expect(searchParams.get("code_challenge_method")).toBe("S256");

      cb(searchParams);
    };

    await _test((searchParams: URLSearchParams) => {
      expect(searchParams.get("identity_provider")).toBeNull();
    });

    await _test((searchParams: URLSearchParams) => {
      expect(searchParams.get("identity_provider")).toBe(
        CognitoIdentityProvider.Apple
      );
    }, CognitoIdentityProvider.Apple);
  });
});
