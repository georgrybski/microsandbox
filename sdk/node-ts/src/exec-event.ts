/** Event emitted by `Sandbox.execStream` and friends. */
export type ExecEvent =
  | { kind: "started"; pid: number }
  | { kind: "stdout"; data: Uint8Array }
  | { kind: "stderr"; data: Uint8Array }
  | { kind: "exited"; code: number }
  | { kind: "interrupted"; reason: TaggedExecDetail; termination: TaggedExecDetail };

/** Tagged interruption detail. A known exit is termination.kind === "exited";
 * "unconfirmed" carries no exit status and must never be treated as success. */
export interface TaggedExecDetail {
  kind: string;
  value?: unknown;
}

/** Internal: the loose shape produced by the native binding. */
export interface RawExecEvent {
  eventType: "started" | "stdout" | "stderr" | "exited" | "interrupted";
  pid?: number;
  data?: Uint8Array;
  code?: number;
}

export function normalizeExecEvent(raw: RawExecEvent): ExecEvent {
  switch (raw.eventType) {
    case "started":
      if (typeof raw.pid !== "number") {
        throw new Error("exec event: missing pid on Started");
      }
      return { kind: "started", pid: raw.pid };
    case "stdout":
      if (!raw.data) throw new Error("exec event: missing data on Stdout");
      return { kind: "stdout", data: raw.data };
    case "stderr":
      if (!raw.data) throw new Error("exec event: missing data on Stderr");
      return { kind: "stderr", data: raw.data };
    case "exited":
      if (typeof raw.code !== "number") {
        throw new Error("exec event: missing code on Exited");
      }
      return { kind: "exited", code: raw.code };
    case "interrupted": {
      if (!raw.data || raw.code != null) throw new Error("exec interruption: missing detail or unexpected exit code");
      const detail = JSON.parse(new TextDecoder().decode(raw.data));
      const reason = detail?.reason;
      const termination = detail?.termination;
      if (!reason || !["timeout", "cancelled", "output_limit", "transport_closed", "protocol", "delivery"].includes(reason.kind)) {
        throw new Error("exec interruption: invalid reason");
      }
      if (!termination || !["exited", "spawn_failed", "unconfirmed"].includes(termination.kind)) {
        throw new Error("exec interruption: invalid termination observation");
      }
      if (termination.kind === "exited" && !Number.isInteger(termination.value)) {
        throw new Error("exec interruption: missing observed exit code");
      }
      if (termination.kind === "unconfirmed" && "value" in termination) {
        throw new Error("exec interruption: unexpected unconfirmed exit value");
      }
      return { kind: "interrupted", reason, termination };
    }
  }
}
