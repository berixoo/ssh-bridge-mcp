const fs = require('fs');
const path = require('path');
const { z } = require('zod');

const HostSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().min(1),
  password: z.string().optional(),
  sudoPassword: z.string().optional(),
});

const ConfigSchema = z
  .object({
    default: z.string().optional(),
    hosts: z.record(z.string(), HostSchema),
  })
  .refine((c) => Object.keys(c.hosts).length > 0, { message: 'at least one host required' });

function configPath() {
  return process.env.SSH_BRIDGE_CONFIG || path.join(__dirname, '..', 'config.json');
}

function loadConfig() {
  const file = configPath();
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (e) {
    throw new Error(`config not found at ${file} (set SSH_BRIDGE_CONFIG to override)`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(`config ${file} is not valid JSON: ${e.message}`);
  }
  const cfg = ConfigSchema.parse(parsed);
  if (cfg.default && !cfg.hosts[cfg.default]) {
    throw new Error(`default host "${cfg.default}" not defined in hosts`);
  }
  return cfg;
}

function resolveHost(cfg, name) {
  const key = name || cfg.default || Object.keys(cfg.hosts)[0];
  const entry = cfg.hosts[key];
  if (!entry) throw new Error(`unknown host "${name}"`);
  return { name: key, ...entry, sudoPassword: entry.sudoPassword ?? entry.password };
}

module.exports = { loadConfig, resolveHost, configPath };
