import { NextResponse } from 'next/server';
import { readFile } from 'fs/promises';
import path from 'path';

const BASE = 'https://app.example.com';

export async function GET(request) {
  const file = request.nextUrl.searchParams.get('file');
  const data = await readFile(path.join('/srv/exports', path.basename(file)), 'utf8');
  return new NextResponse(data);
}

export async function POST(request) {
  const body = await request.json();
  const target = body.returnTo;
  if (typeof target === 'string' && target.startsWith('/') && !target.startsWith('//')) {
    return NextResponse.redirect(new URL(target, BASE));
  }
  return NextResponse.redirect(new URL('/', BASE));
}
