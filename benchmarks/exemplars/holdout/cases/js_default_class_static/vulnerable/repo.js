import { exec } from 'child_process';

export default class Archiver {
  static pack(dir) {
    exec('tar czf out.tgz ' + dir);
  }
}
