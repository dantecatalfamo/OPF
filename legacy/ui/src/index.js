import React from 'react';
// import { createRoot } from 'react-dom/client';
import ReactDOM from 'react-dom';
import App from './Components/App';
import './index.css';
import * as serviceWorker from './serviceWorker';

const container = document.getElementById('root');
ReactDOM.render(<App />, container);

// Disable react 18 mode until antd is fixed
// https://github.com/ant-design/ant-design/issues/34890
// https://github.com/ant-design/ant-design/projects/7#card-80292346=
// const root = createRoot(container);
// root.render(<App />);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
