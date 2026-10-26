import React from 'react';
import { useSearchParams } from 'react-router-dom';
import DOMPurify from 'dompurify';

export function Banner() {
  const [params] = useSearchParams();
  const message = params.get('msg');
  return (
    <div className="banner">
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(message) }} />
    </div>
  );
}
