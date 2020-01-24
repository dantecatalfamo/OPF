import React, { useState, useLayoutEffect } from 'react';

export async function getJSON(url) {
  const response = await fetch(url);
  return await response.json();
}

export async function postJSON(url, data) {
  const response = await fetch(url, {
    method: 'POST',
    body: JSON.stringify(data),
  });
  return await response.json();
}

// https://stackoverflow.com/a/19014495
export function useWindowSize() {
  const [size, setSize] = useState([0, 0]);
  useLayoutEffect(() => {
    function updateSize() {
      setSize([window.innerWidth, window.innerHeight]);
    }
    window.addEventListener('resize', updateSize);
    updateSize();
    return () => window.removeEventListener('resize', updateSize);
  }, []);
  return size;
}
