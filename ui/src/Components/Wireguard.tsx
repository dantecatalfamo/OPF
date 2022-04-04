import { useState } from 'react';
import { serverURL } from '../config';
import { useJsonUpdates } from '../helpers';

const wireguardURL = `${serverURL}/api/wireguard-interfaces`;

/* interface WireguardProps {
 * } */

export default function Wireguard() {
  const [wgData, setWgData] = useState({});
  useJsonUpdates(wireguardURL, setWgData, 5 * 1000);
  return JSON.stringify(wgData);
}
