import { exec } from 'child_process';

export function listDir(dir: string) {
  exec('ls ' + dir);
}
