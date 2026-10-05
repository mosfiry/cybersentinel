"use strict";

function hideWindowOnClose(event, { quitting, trayAvailable, hide }) {
  if (quitting || !trayAvailable || !event || typeof event.preventDefault !== "function" || typeof hide !== "function") {
    return false;
  }
  event.preventDefault();
  hide();
  return true;
}

function keepProcessAfterWindowClosure({ trayAvailable, quitting }) {
  return Boolean(trayAvailable) && !Boolean(quitting);
}

module.exports = { hideWindowOnClose, keepProcessAfterWindowClosure };
