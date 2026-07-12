"use strict";
import gradient from 'gradient-string';
import makeWASocket from './Socket/index.js';
const banner = `
░█░█░█▀█░█▀█░█▀▀░█▀█░█▄█░█▀█░█░░
░█▀█░█▀█░█░█░▀▀█░█▀█░█░█░█▀█░█░░
░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀

░█▀█░█▀▀░█▀▀
░█░█░█▀▀░█░░
░▀▀▀░▀░░░▀▀▀
`;

const info = `
┌───────────────────────────────────────────────────────────────────────┐
│                         👑 IMALKA HANSAMAL 👑                         │
├───────────────────────────────────────────────────────────────────────┤
│  ⚡ Status: Online & Active                                           │
│  🚀 Building Ideas Into Reality                                       │
│  ✨ Creativity • Innovation • Technology                              │
│  🔐 Smart • Fast • Reliable                                           │
│  📱 Always Connected • Always Growing                                 │
├───────────────────────────────────────────────────────────────────────┤
│              💫 Welcome To IMALKA HANSAMAL World 💫                   │
└───────────────────────────────────────────────────────────────────────┘
`;

// Print banner with gradient
console.log(gradient(['#ff0000', '#ff7f00', '#ffff00', '#00ff00', '#0000ff', '#4b0082', '#9400d3'])(banner));

// Print info with gradient
console.log(gradient(['#FFD700', '#FF6B6B', '#4ECDC4'])(info));

// Startup message
console.log(gradient(['#00FF88', '#FFFFFF'])('\n🎯 Initializing Baileys...\n'));

export * from '../WAProto/index.js';
export * from './Utils/index.js';
export * from './Store/index.js';
export * from './Types/index.js';
export * from './Defaults/index.js';
export * from './WABinary/index.js';
export * from './WAM/index.js';
export * from './WAUSync/index.js';
export * from './Socket/index.js';
export default makeWASocket;
