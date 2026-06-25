import dotenv from "dotenv";

dotenv.config();

const userName = process.argv[2] || "Chetan";
const dealerNoArg = process.argv[3] || "1";
const apiBase = (process.env.API_BASE || process.env.EXPO_PUBLIC_API_URL || "http://localhost:4000").replace(
  /\/$/,
  ""
);

async function main() {
  const res = await fetch(`${apiBase}/dealers/relink-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ userName, dealerNo: dealerNoArg }),
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    throw new Error(data?.error || text || `Request failed (${res.status})`);
  }
  console.log(data.message || "Dealer relinked.");
  console.log(JSON.stringify(data.dealer, null, 2));
}

await main().catch((err) => {
  console.error(err.message || err);
  process.exitCode = 1;
});
