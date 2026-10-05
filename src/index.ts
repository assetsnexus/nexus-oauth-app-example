import { assertConfig, loadConfig } from './config.js';
import { listen } from './http-server.js';

const config = loadConfig();
assertConfig(config);
const server = await listen(config);
const address = server.address();
const port = address && typeof address === 'object' ? address.port : config.port;
console.info(JSON.stringify({ message: 'login-with-nexus-partner listening', port }));
