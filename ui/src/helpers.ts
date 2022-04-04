import { useState, useEffect, useLayoutEffect } from 'react';

export async function getJSON(url: string) {
  const response = await fetch(url);
  return response.json();
}

export async function postJSON(url: string, data: object) {
  const response = await fetch(url, {
    method: 'POST',
    body: JSON.stringify(data),
  });
  return response.json();
}

export function useJSON(url: string, setter: (data: object) => void) {
  useEffect(() => {
    getJSON(url).then((res) => setter(res));
  }, [url]);
}

export function useJsonUpdates(url: string, setter: (data: any) => void, updateTime: number) {
  useEffect(() => {
    getJSON(url).then((res) => setter(res));
    const interval = setInterval(() => {
      getJSON(url).then((res) => setter(res));
    }, updateTime);

    return () => clearInterval(interval);
  }, [url, updateTime]);
}

export function timeSince(time: number) {
  const startTime = new Date(time);
  const now = new Date();
  const timeBetween = now.getTime() - startTime.getTime();
  let hours;
  let minutes;
  let seconds;
  seconds = Math.floor(timeBetween / 1000);
  minutes = Math.floor(seconds / 60);
  seconds %= 60;
  hours = Math.floor(minutes / 60);
  minutes %= 60;
  const days = Math.floor(hours / 24);
  hours %= 24;
  return {
    days,
    hours,
    minutes,
    seconds,
  };
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

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
export async function digestMessage(message: string) {
  const msgUint8 = new TextEncoder().encode(message); // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8); // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
  return hashHex;
}

export async function stringToColor(str: string) {
  const hash = await digestMessage(str);
  const color = hash.slice(0, 6);
  return `#${color}`;
}
