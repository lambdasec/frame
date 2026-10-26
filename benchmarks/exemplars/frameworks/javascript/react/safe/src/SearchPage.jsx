import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

export default function SearchPage() {
  const [params] = useSearchParams();
  const [results, setResults] = useState([]);
  const q = params.get('q');

  useEffect(() => {
    fetch('/api/search?q=' + encodeURIComponent(q)).then((r) => r.json()).then(setResults);
  }, [q]);

  return (
    <div>
      <h2>Results for {q}</h2>
      <ul>{results.map((r) => <li key={r.id}>{r.title}</li>)}</ul>
    </div>
  );
}
