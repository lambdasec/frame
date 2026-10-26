'use server';

import { revalidatePath } from 'next/cache';
import { exec } from 'child_process';

export async function generateReport(formData) {
  const month = formData.get('month');
  exec('./bin/report --month ' + month);  // frame-expect: CWE-78
  revalidatePath('/reports');
}
