/**
 * Generic Fastify bootstrap skeleton — the common server setup shared by every UBLP agent
 * (ublp-agent, the future incoterms-escrow settlement agent). Routes/schemas stay in each
 * module's own "plugin" layer (see AGENTS.md Section 4.2) — this file is just the skeleton.
 */

import Fastify, { FastifyInstance } from 'fastify';

export interface AgentServerConfig {
  port: number;
  host?: string;
  logger?: boolean;
}

export function createAgentServer(config: Pick<AgentServerConfig, 'logger'> = {}): FastifyInstance {
  return Fastify({ logger: config.logger ?? false });
}

export async function startAgentServer(
  app: FastifyInstance,
  config: AgentServerConfig
): Promise<void> {
  await app.listen({ port: config.port, host: config.host ?? '0.0.0.0' });
}
