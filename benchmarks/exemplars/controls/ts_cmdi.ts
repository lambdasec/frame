import { exec } from 'child_process';
export function list(req: any, res: any) { exec('ls ' + req.query.dir); res.send('ok'); }
