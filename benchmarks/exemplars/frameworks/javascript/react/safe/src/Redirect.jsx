import React, { useEffect } from 'react';

export default function Redirect() {
  useEffect(() => {
    const next = new URLSearchParams(window.location.search).get('next');
    if (next && next.startsWith('/') && !next.startsWith('//')) {
      window.location.href = next;
    }
  }, []);
  return null;
}
