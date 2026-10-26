import { exec } from 'child_process';

export class Shell {
  run(dir: string) {
    exec('ls ' + dir);
  }
}
