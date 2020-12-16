import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export default async (): Promise<void> => {
  if (process.env.CI) {
    await execAsync('npm run build:test');
  }
};
