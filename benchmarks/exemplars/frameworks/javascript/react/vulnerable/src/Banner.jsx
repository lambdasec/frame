import React from 'react';
import { useSearchParams } from 'react-router-dom';

export function Banner() {
  const [params] = useSearchParams();
  const message = params.get('msg');
  return (
    <div className="banner">
      <div dangerouslySetInnerHTML={{ __html: message }} />  {/* frame-expect: CWE-79 */}
    </div>
  );
}
