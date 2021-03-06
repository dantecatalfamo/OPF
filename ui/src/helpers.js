import { useState, useEffect, useLayoutEffect } from 'react';

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

export function useJSON(url, setter) {
  useEffect(() => {
    getJSON(url).then(res => setter(res));
  }, [url]);
}

export function useJsonUpdates(url, setter, updateTime) {
  useEffect(() => {
    getJSON(url).then(res => setter(res));
    const interval = setInterval(() => {
      getJSON(url).then(res => setter(res));
    }, updateTime);

    return () => clearInterval(interval);
  }, [url, updateTime]);
}

export function timeSince(time) {
  const startTime = new Date(time);
  const now = new Date();
  const timeBetween = now - startTime;
  let days, hours, minutes, seconds;
  seconds = Math.floor(timeBetween / 1000);
  minutes = Math.floor(seconds / 60);
  seconds = seconds % 60;
  hours = Math.floor(minutes / 60);
  minutes = minutes % 60;
  days = Math.floor(hours / 24);
  hours = hours % 24;
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
