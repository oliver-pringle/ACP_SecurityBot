import type { Offering } from "./types.js";
import { requireStringLength } from "../validators.js";

const MAX_MESSAGE_LENGTH = 10_000;

export const echo: Offering = {
  name: "echo",
  description:
    "Echo a message back. One-shot offering. Demonstrates the SecurityBot pattern handles vanilla one-shot calls alongside subscription offerings.",
  slaMinutes: 5, // SQLite write only; sub-second  -  min SLA
  requirementSchema: {
    type: "object",
    properties: {
      message: { type: "string", description: "The message to echo back.", maxLength: MAX_MESSAGE_LENGTH }
    },
    required: ["message"]
  },
  requirementExample: {
    message: "hello world"
  },
  deliverableSchema: {
    type: "object",
    properties: {
      id:         { type: "integer", description: "SQLite row id assigned to this echo." },
      message:    { type: "string",  description: "The message echoed back, verbatim." },
      receivedAt: { type: "string",  description: "ISO-8601 UTC timestamp the API recorded the message." }
    },
    required: ["id", "message", "receivedAt"]
  },
  deliverableExample: {
    id: 42,
    message: "hello world",
    receivedAt: "2026-05-04T14:23:11.4127831Z"
  },
  validate(req) {
    return requireStringLength(req.message, "message", MAX_MESSAGE_LENGTH);
  },
  async execute(req, { client }) {
    return await client.echo({ message: String(req.message) });
  }
};
