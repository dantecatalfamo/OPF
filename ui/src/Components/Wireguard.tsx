import React, {useState} from 'react';
import { serverURL } from '../config';

const wireguardURL = `${serverURL}/api/wireguard`;

interface WireguardProps {
}

export default function Wireguard (props: WireguardProps) {
  return wireguardURL
}
