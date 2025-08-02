// Jest setup file
import 'jest';

// Mock console methods to avoid cluttering test output
global.console = {
  ...console,
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

// Setup global test environment
beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();
});
