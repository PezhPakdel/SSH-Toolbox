<script lang="ts">
  import { untrack } from "svelte";
  import { wolSend } from "../backend/net";

  interface Props {
    mac?: string;
    host?: string;
    onclose: () => void;
  }

  let { mac = "", host = "", onclose }: Props = $props();
  let address = $state(untrack(() => mac));
  let directed = $state(untrack(() => host));
  let error = $state("");
  let done = $state("");
  let sending = $state(false);

  async function send() {
    sending = true;
    error = "";
    done = "";
    try {
      await wolSend(address.trim(), directed.trim());
      done = "Wake packet sent. The computer only wakes if it is set to allow that, and if it is on the same network.";
    } catch (err) {
      error = (err as { message?: string }).message ?? "Couldn't send the wake packet.";
    } finally {
      sending = false;
    }
  }
</script>

<div class="modal-backdrop">
  <div
    class="modal"
    role="dialog"
    aria-label="Wake a computer"
    tabindex="-1"
    onkeydown={(e) => {
      if (e.key === "Escape") onclose();
      e.stopPropagation();
    }}
  >
    <h2>Wake a computer</h2>
    <p class="sub">Sends a wake-on-LAN packet to the whole network, and also straight to the host if you fill that in.</p>
    <label class="field">
      MAC address
      <input type="text" bind:value={address} spellcheck="false" placeholder="aa:bb:cc:dd:ee:ff" />
    </label>
    <label class="field">
      Host (optional)
      <input type="text" bind:value={directed} spellcheck="false" placeholder="10.0.0.5" />
    </label>
    {#if error}<p class="message error">{error}</p>{/if}
    {#if done}<p class="message ok">{done}</p>{/if}
    <div class="modal-actions">
      <button class="btn" onclick={onclose}>Close</button>
      <button class="btn primary" disabled={sending} onclick={send}>{sending ? "Sending…" : "Wake"}</button>
    </div>
  </div>
</div>
