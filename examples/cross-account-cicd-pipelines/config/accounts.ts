export interface AccountConfig {
  accountId: string;
  region: string;
  githubRepository: string;
  email: string;
}

export interface AccountsConfig {
  [environment: string]: AccountConfig;
}

// Load configuration from accounts.json
let config: AccountsConfig;

try {
  config = require('./accounts.json');
} catch (error) {
  console.warn('accounts.json not found, using example configuration');
  config = require('./accounts.example.json');
}

export const accountConfig: AccountsConfig = config;
