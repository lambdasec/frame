import React, { useEffect } from 'react';

export default function Redirect() {
  useEffect(() => {
    const next = new URLSearchParams(window.location.search).get('next');
    window.location.href = next;  // frame-expect: CWE-601
  }, []);
  return null;
}
