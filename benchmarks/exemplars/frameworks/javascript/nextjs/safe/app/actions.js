'use server';

import { revalidatePath } from 'next/cache';
import { execFile } from 'child_process';

export async function generateReport(formData) {
  const month = formData.get('month');
  execFile('./bin/report', ['--month', month]);
  revalidatePath('/reports');
}
