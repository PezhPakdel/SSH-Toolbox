<script lang="ts">
  import { untrack } from "svelte";
  import { netPing, netTrace } from "../backend/net";

  interface Props {
    kind: "ping" | "trace";
    host?: string;
    onclose: () => void;
  }

  let { kind, host = "", onclose }: Props = $props();
  let address = $state(untrack(() => host));
  let output = $state("");
  let error = $state("");
  let running = $state(false);

  const title = $derived(kind === "ping" ? "Ping" : "Traceroute");

  async function run() {
    const target = address.trim();
    if (!target) {
      error = "Enter a host name or address.";
      return;
    }
    running = true;
    error = "";
    output = "";
    try {
      output = kind === "ping" ? await netPing(target) : await netTrace(target);
    } catch (err) {
      error = (err as { message?: string }).message ?? "That didn't work.";
    } finally {
      running = false;
    }
  }
</script>

<div class="modal-backdrop">
  <div
    class="modal wide"
    role="dialog"
    aria-label={title}
    tabindex="-1"
    onkeydown={(e) => {
      if (e.key === "Escape") onclose();
      e.stopPropagation();
    }}
  >
    <h2>{title}</h2>
    <p class="sub">
      {kind === "ping"
        ? "Sends four pings and shows the replies. Useful before you open a session."
        : "Shows the path packets take to that computer. On Linux this needs traceroute to be installed."}
    </p>
    <div class="row">
      <label class="field grow">
        Host
        <input type="text" bind:value={address} spellcheck="false" onkeydown={(e) => e.key === "Enter" && run()} />
      </label>
      <button class="btn primary" disabled={running} onclick={run}>{running ? "Working…" : "Run"}</button>
    </div>
    {#if error}<p class="message error">{error}</p>{/if}
    {#if output}<pre class="out">{output}</pre>{/if}
    <div class="modal-actions">
      <button class="btn" onclick={onclose}>Close</button>
    </div>
  </div>
</div>

<style>
  .row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
  }
  .out {
    max-height: 320px;
    overflow: auto;
    margin: 0;
    padding: 10px 12px;
    white-space: pre-wrap;
    font: 12px var(--mono);
    color: var(--text);
    background: var(--bg-0);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
</style>
