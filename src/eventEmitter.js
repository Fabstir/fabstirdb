// src/eventEmitter.js
const events = {};

const on = (event, listener) => {
  if (!events[event]) {
    events[event] = [];
  }
  events[event].push(listener);
};

const emit = (event, ...args) => {
  if (events[event]) {
    events[event].forEach((listener) => {
      listener(...args);
    });
  }
};

const off = (event, listener) => {
  if (events[event]) {
    const idx = events[event].indexOf(listener);
    if (idx > -1) {
      events[event].splice(idx, 1);
    }
  }
};

export const eventEmitter = { on, emit, off };
