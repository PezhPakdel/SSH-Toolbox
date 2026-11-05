// Wake-on-LAN, ping, traceroute, the link-time check, and the connection card.
import { invoke } from "@tauri-apps/api/core";
import type { SessionsFile } from "./index";

export interface ConnectionCard {
  /** An ssh command for a terminal. */
  command: string;
  /** A short note you can paste into a chat. No passwords. */
  card: string;
}

export function connectionCard(file: SessionsFile, sessionId: string): Promise<ConnectionCard> {
  return invoke<ConnectionCard>("connection_card", { file, sessionId });
}

/** Broadcasts a wake packet. `host` may be empty. */
export function wolSend(mac: string, host: string): Promise<void> {
  return invoke<void>("wol_send", { mac, host });
}

export function netPing(host: string): Promise<string> {
  return invoke<string>("net_ping", { host });
}

export function netTrace(host: string): Promise<string> {
  return invoke<string>("net_trace", { host });
}

/** Milliseconds to open a TCP connection. */
export function linkProbe(host: string, port: number): Promise<number> {
  return invoke<number>("link_probe", { host, port });
}
