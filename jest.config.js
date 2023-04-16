module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.tsx?$",
  testPathIgnorePatterns: [
    "/node_modules/",
    "/dist/",
    "/lib/",
    "/build/",
    "/cdk.out/",
    ".d.ts",
  ],
  passWithNoTests: true,
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: "tsconfig.json",
      },
    ],
  },
  testTimeout: 30000,
};
