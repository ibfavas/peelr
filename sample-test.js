// TODO: remove before production
// SECURITY: test fixture for Peelr CLI validation

const supportEmail = "security@example.com";
const apiKey = "AIzaSyD3MO-TEST-KEY-1234567890abcd";
const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.signature";
const dbPassword = "super-secret-password";

function renderProfile(name, markup) {
  const endpoint = "/api/v1/profile?email=security@example.com&token=demo-token";
  fetch(endpoint, {
    headers: {
      Authorization: `Bearer ${jwtToken}`,
      "X-API-Key": apiKey,
    },
  });

  document.getElementById("name").innerHTML = name;
  document.write(markup);
}

renderProfile("demo", "<img src=x onerror=alert(1)>");
