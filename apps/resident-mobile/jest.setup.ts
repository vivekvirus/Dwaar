jest.mock("@react-native-async-storage/async-storage", () => require("@react-native-async-storage/async-storage/jest/async-storage-mock"));

// expo-crypto: CSPRNG from node for the UUIDv7 generator
jest.mock("expo-crypto", () => ({
  getRandomValues: (a: Uint8Array) => require("node:crypto").webcrypto.getRandomValues(a),
}));

jest.mock("expo-secure-store", () => {
  const mem = new Map<string, string>();
  return {
    getItemAsync: jest.fn(async (k: string) => mem.get(k) ?? null),
    setItemAsync: jest.fn(async (k: string, v: string) => void mem.set(k, v)),
    deleteItemAsync: jest.fn(async (k: string) => void mem.delete(k)),
    __mem: mem,
  };
});

jest.mock("expo-router", () => {
  const router = { push: jest.fn(), replace: jest.fn(), dismissTo: jest.fn(), back: jest.fn(), canGoBack: jest.fn(() => true) };
  return { useRouter: () => router, __router: router };
});
