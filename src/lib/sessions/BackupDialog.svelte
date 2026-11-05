<script lang="ts">
  // Back up the saved sessions to one file, and bring them back on another computer. The file
  // holds hosts, users and key file paths, but no passwords and no key contents.

  import { mobaImport, sessionsExport, sessionsImport, type MergeResult, type MobaReport } from "../backend";
  import { pickOpenFile } from "../backend/dialog";
  import type { Library } from "./library.svelte";

  interface Props {
    library: Library;
    onclose: () => void;
  }

  let { library, onclose }: Props = $props();

  let busy = $state(false);
  let saved = $state("");
  let path = $state("");
  let result = $state<MergeResult | null>(null);
  let moba = $state<MobaReport | null>(null);
  let mobaPath = $state("");
  let error = $state("");

  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    busy = true;
    error = "";
    try {
      return await action();
    } catch (e) {
      error = (e as { message?: string }).message ?? "That didn't work.";
    } finally {
      busy = false;
    }
  }

  async function backup() {
    saved = (await run(sessionsExport)) ?? "";
    result = null;
  }

  async function restore() {
    const done = await run(() => sessionsImport(path));
    if (!done) return;
    result = done;
    moba = null;
    saved = "";
    await library.load().catch(() => {});
  }

  async function browseBackup() {
    const picked = await pickOpenFile("SSH Toolbox sessions", ["toml"]);
    if (picked) path = picked;
  }

  async function browseMoba() {
    const picked = await pickOpenFile("MobaXterm sessions", ["mxtsessions", "mobaconf", "ini", "moba"]);
    if (picked) mobaPath = picked;
  }

  async function importMoba() {
    const done = await run(() => mobaImport(mobaPath));
    if (!done) return;
    moba = done;
    result = null;
    saved = "";
    await library.load().catch(() => {});
  }
</script>

<div class="modal-backdrop">
  <div
    class="modal"
    role="dialog"
    aria-label="Configurations"
    tabindex="-1"
    onkeydown={(e) => {
      if (e.key === "Escape") onclose();
      e.stopPropagation();
    }}
  >
    <h2>Configurations</h2>

    <h3>Export</h3>
    <p class="lead">
      Saves your sessions and folders to a file in your Downloads folder. It has no passwords and
      no private keys, only the names of key files. Passwords saved in the keychain are not
      included, so they are asked for again on the new computer.
    </p>
    <button class="btn primary" disabled={busy} onclick={backup}>Export sessions</button>
    {#if saved}<p class="message ok">Saved to {saved}</p>{/if}

    <h3>Import an SSH Toolbox backup</h3>
    <label class="field">
      Backup file
      <span class="pick">
        <input type="text" bind:value={path} placeholder="Path of a sessions backup (.toml)" spellcheck="false" />
        <button class="btn" type="button" disabled={busy} onclick={browseBackup}>Browse…</button>
      </span>
      <small>
        Sessions that aren't here yet are added. The ones you already have are left as they are.
        Trusted FTPS certificates are not restored: you are asked to accept them again.
      </small>
    </label>
    <button class="btn" disabled={busy || !path.trim()} onclick={restore}>Restore</button>
    {#if result}
      <p class="message ok">
        Added {result.sessions_added} {result.sessions_added === 1 ? "session" : "sessions"} and
        {result.folders_added} {result.folders_added === 1 ? "folder" : "folders"}.
        {#if result.skipped > 0}{result.skipped} already here, left as they are.{/if}
      </p>
    {/if}

    <h3>Import from MobaXterm</h3>
    <label class="field">
      MobaXterm file
      <span class="pick">
        <input type="text" bind:value={mobaPath} placeholder="Sessions export, configuration, or MobaXterm.ini" spellcheck="false" />
        <button class="btn" type="button" disabled={busy} onclick={browseMoba}>Browse…</button>
      </span>
      <small>
        Use a session export (.mxtsessions), a full configuration (.mobaconf), or MobaXterm.ini.
        SSH and SFTP sessions are added, including folders and jump hosts. Passwords are not copied.
        Remote desktop and VNC sessions are skipped.
      </small>
    </label>
    <button class="btn" disabled={busy || !mobaPath.trim()} onclick={importMoba}>Import MobaXterm sessions</button>
    {#if moba}
      <p class="message ok">
        Added {moba.sessions_added} {moba.sessions_added === 1 ? "session" : "sessions"} and
        {moba.folders_added} {moba.folders_added === 1 ? "folder" : "folders"}.
        {#if moba.skipped > 0}{moba.skipped} already here, left as they are.{/if}
      </p>
      {#if moba.left_out.length}
        <ul>{#each moba.left_out as line (line)}<li>{line}</li>{/each}</ul>
      {/if}
    {/if}

    {#if error}<p class="message error">{error}</p>{/if}
    <div class="modal-actions"><button class="btn primary" onclick={onclose}>Close</button></div>
  </div>
</div>

<style>
  h3 {
    margin: 16px 0 6px;
    font-size: 13px;
  }
  .pick {
    display: flex;
    gap: 8px;
  }
  .pick input {
    flex: 1;
    min-width: 0;
  }
</style>
