// Choosing a file or folder with the system dialog. Only this folder may import Tauri.
import { open } from "@tauri-apps/plugin-dialog";

function one(picked: string | string[] | null): string | null {
  return typeof picked === "string" ? picked : null;
}

/** A folder on this computer, or nothing if the dialog was cancelled. */
export async function pickDirectory(title: string): Promise<string | null> {
  const picked = await open({ directory: true, multiple: false, title });
  return one(picked);
}

/** One or more files, or an empty list if the dialog was cancelled. */
export async function pickFiles(title: string): Promise<string[]> {
  const picked = await open({ directory: false, multiple: true, title });
  if (typeof picked === "string") return [picked];
  return Array.isArray(picked) ? picked : [];
}

/** One file of the given kinds, such as "toml" or "mxtsessions". */
export async function pickOpenFile(title: string, extensions: string[]): Promise<string | null> {
  const picked = await open({
    directory: false,
    multiple: false,
    title,
    filters: [{ name: title, extensions }],
  });
  return one(picked);
}
