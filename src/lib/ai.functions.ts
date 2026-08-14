import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { runAegisAI } from "./ai.server";
import type { AegisAction, AegisRequest } from "./ai.server";

const aegisSchema = z.object({
  action: z.string(),
  userContent: z.string().optional(),
  messages: z
    .array(
      z.object({
        role: z.enum(["system", "user", "assistant"]),
        content: z.string(),
      }),
    )
    .optional(),
});

export const aegisAI = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => aegisSchema.parse(data))
  .handler(async ({ data }) => {
    const envelope = await runAegisAI({
      action: data.action as AegisAction,
      userContent: data.userContent,
      messages: data.messages,
    } as AegisRequest);
    // The result shape depends on the action; keep it opaque across the wire.
    return envelope as { ok: boolean; result: any };
  });
