import { NextResponse } from 'next/server';
import { readFile } from 'fs/promises';

export async function GET(request) {
  const file = request.nextUrl.searchParams.get('file');
  const data = await readFile('/srv/exports/' + file, 'utf8');  // frame-expect: CWE-22
  return new NextResponse(data);
}

export async function POST(request) {
  const body = await request.json();
  return NextResponse.redirect(body.returnTo);  // frame-expect: CWE-601
}
