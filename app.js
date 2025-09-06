import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

app.get('/access_token', (req, res) => {
  try {
    const accessToken = req.headers['x-forwarded-access-token'];

    if (!accessToken) {
      return sendErrorHtmlResponse(
        res,
        'Missing X-Forwarded-Access-Token header'
      );
    }

    return sendTokenHtmlResponse(res, decoded);
  } catch (error) {
    return sendErrorHtmlResponse(
      res,
      `Failed to parse the jwt with message ${error.message}`
    );
  }
});

app.get('/id_token', (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return sendErrorHtmlResponse(res, 'Missing Authorization header');
    }

    const idToken = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : authHeader;

    if (!idToken) {
      return sendErrorHtmlResponse(
        res,
        'Invalid Authorization header format. Expected: Bearer <token>'
      );
    }

    return sendTokenHtmlResponse(res, decoded);
  } catch (error) {
    return sendErrorHtmlResponse(
      res,
      `Failed to parse token with error: ${error.message}`
    );
  }
});

app.get('/sign_out', (req, res) => {
  res.set('HX-Redirect', '/oauth2/sign_in');

  return res.send();
});

function sendTokenHtmlResponse(res, jwtToken) {
  const decodedJwt = jwt.decode(jwtToken, { complete: true });

  if (!decodedJwt) {
    return sendErrorHtmlResponse(res, 'Invalid jwt');
  }

  const formattedToken = formatJSON(decodedJwt);
  const highlightedToken = highlightJSON(formattedToken);

  return res.send(`
        <div class="json-container">
          <button class="copy-btn" disabled>Copy</button>
          <div class="json-content">${highlightedToken}</div>
        </div>
      `);
}

function sendErrorHtmlResponse(res, errorMessage) {
  return res.send(`<div class="error">${errorMessage}</div>`);
}

function highlightJSON(jsonString) {
  return jsonString.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    function (match) {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    }
  );
}

function formatJSON(obj) {
  return JSON.stringify(obj, null, 2);
}

app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});

export default app;
