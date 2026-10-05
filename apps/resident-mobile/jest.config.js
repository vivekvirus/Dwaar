module.exports = {
  preset: "jest-expo",
  setupFilesAfterEnv: ["<rootDir>/jest.setup.ts"],
  testMatch: ["<rootDir>/__tests__/**/*.test.{ts,tsx}"],
  testPathIgnorePatterns: ["/node_modules/", "/dist/", "/e2e/"],
  collectCoverageFrom: ["src/**/*.{ts,tsx}", "!src/api/generated/**"],
};
