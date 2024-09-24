chrome.runtime.onInstalled.addListener(() => {
    console.log('Email Filter extension installed.');
  });
  
  function getAccessToken(callback) {
    chrome.identity.launchWebAuthFlow(
      {
        url: `https://accounts.google.com/o/oauth2/auth?client_id=YOUR_CLIENT_ID.apps.googleusercontent.com&redirect_uri=https://<YOUR_EXTENSION_ID>.chromiumapp.org/&response_type=token&scope=https://www.googleapis.com/auth/gmail.readonly`,
        interactive: true
      },
      function (redirectUrl) {
        if (chrome.runtime.lastError || !redirectUrl) {
          console.error(chrome.runtime.lastError);
          return;
        }
        const accessToken = new URL(redirectUrl).hash.split('&')[0].split('=')[1];
        callback(accessToken);
      }
    );
  }
  
  function readLatestEmail(accessToken) {
    fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1', {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    })
      .then(response => response.json())
      .then(data => {
        if (data.messages && data.messages.length > 0) {
          const messageId = data.messages[0].id;
          fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}`, {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          })
            .then(response => response.json())
            .then(message => {
              const subject = message.payload.headers.find(header => header.name === 'Subject').value;
              const from = message.payload.headers.find(header => header.name === 'From').value;
              console.log(`From: ${from}`);
              console.log(`Subject: ${subject}`);
            });
        } else {
          console.log('No new messages.');
        }
      });
  }
  
  // Listen for messages from the popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getEmails') {
      getAccessToken(accessToken => {
        readLatestEmail(accessToken);
        sendResponse({ status: 'done' });
      });
      return true; // Keep the message channel open for asynchronous response
    }
  });
  