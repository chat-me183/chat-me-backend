export default {
  async fetch(request, env) {
    // Only your site is allowed to talk to this backend.
    const allowedOrigin = 'https://chat-me183.github.io';

    // Browsers send an OPTIONS request first to check permission - answer it.
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(allowedOrigin) });
    }

    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Only POST requests allowed' }, allowedOrigin, 405);
    }

    try {
      const body = await request.json();
      const token = body.token;
      if (!token) {
        return jsonResponse({ success: false, error: 'Missing token' }, allowedOrigin);
      }

      // Ask Google directly: is this reCAPTCHA response real?
      const verifyRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=${env.RECAPTCHA_SECRET}&response=${token}`
      });
      const verifyData = await verifyRes.json();

      return jsonResponse({ success: verifyData.success === true }, allowedOrigin);
    } catch (e) {
      return jsonResponse({ success: false, error: 'Server error' }, allowedOrigin, 500);
    }
  }
};

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

function jsonResponse(obj, origin, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
  });
}
