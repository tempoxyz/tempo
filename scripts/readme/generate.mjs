import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import Handlebars from "handlebars";

const { values } = parseArgs({ options: { check: { type: "boolean", default: false } } });
const root = new URL("../../", import.meta.url);
const data = Object.fromEntries(
  ["mainnet", "testnet"].map((network) => [
    network,
    JSON.parse(readFileSync(new URL(`${network}-network-identity.json`, root), "utf8")),
  ]),
);
const template = readFileSync(new URL("README.md.hbs", root), "utf8");
const rendered = Handlebars.compile(template, { strict: true, noEscape: true })(data);
const readme = new URL("README.md", root);

if (values.check) {
  const current = existsSync(readme) ? readFileSync(readme, "utf8") : "";
  if (current !== rendered) {
    console.error("README.md is stale; run: npm --prefix scripts/readme run generate");
    process.exitCode = 1;
  }
} else {
  writeFileSync(readme, rendered, "utf8");
}
