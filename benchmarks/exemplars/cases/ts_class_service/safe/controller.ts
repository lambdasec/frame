import { Shell } from './shell';

export class Controller {
  constructor(private readonly shell: Shell) {}

  list(req: any, res: any) {
    this.shell.run('/tmp');
    res.send('ok');
  }
}
